<?php
/**
 * Scheduled scans, cron ticking, and manifest trust management.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Owns the schedule for background scans and the trust helpers used by
 * decisions and the install gate.
 *
 * A scheduled scan starts an incremental job and ticks it once; if the job is
 * still running it schedules a one-off 'wpcybersec_scan_tick' event 60 seconds
 * later, which keeps rescheduling itself until the job finishes. This turns the
 * single scheduled event into a chain of short, resumable ticks.
 */
class File_Monitor {

	const SCHEDULED_HOOK = 'wpcybersec_scheduled_scan';
	const TICK_HOOK      = 'wpcybersec_scan_tick';
	const TICK_DELAY     = 60;
	/** Seconds per cron tick; Scan_Job::tick() also keeps it under half of what max_execution_time leaves. */
	const CRON_BUDGET    = 20.0;

	/** Rebaseline no more than this many files synchronously (e.g. a plugin folder). */
	const REBASELINE_MAX = 6000;

	/**
	 * Hooks.
	 */
	public function register() {
		add_action( self::SCHEDULED_HOOK, array( $this, 'run_scheduled_scan' ) );
		add_action( self::TICK_HOOK, array( $this, 'run_tick' ) );
		add_action( 'wpcybersec_settings_updated', array( $this, 'maybe_reschedule' ), 10, 2 );
		add_action( 'wpcybersec_settings_updated', array( $this, 'maybe_reset_baseline' ), 10, 2 );

		// Scans are scheduled on the main site only (one scan for a whole
		// multisite network); other sites never check the schedule.
		if ( ! Network::is_main() ) {
			return;
		}

		// Scheduling runs the cron_schedules filter, where other plugins call
		// __(): before init that loads translations too early (notice since
		// WordPress 6.7). The 'weekly' interval ships with core (5.4+).
		if ( did_action( 'init' ) ) {
			$this->ensure_schedule();
		} else {
			add_action( 'init', array( $this, 'ensure_schedule' ), 20 );
		}
	}

	/**
	 * Schedules the background scan according to scan_schedule.
	 */
	public function ensure_schedule() {
		$schedule = (string) wpcybersec()->settings->get( 'scan_schedule', 'twicedaily' );
		if ( 'off' === $schedule ) {
			Network::clear_hook( self::SCHEDULED_HOOK );
			return;
		}
		$valid = array( 'hourly', 'twicedaily', 'daily', 'weekly' );
		if ( ! in_array( $schedule, $valid, true ) ) {
			$schedule = 'twicedaily';
		}

		$current = Network::get_schedule( self::SCHEDULED_HOOK );
		if ( $current === $schedule ) {
			return;
		}
		Network::clear_hook( self::SCHEDULED_HOOK );
		Network::schedule_event( time() + 5 * MINUTE_IN_SECONDS, $schedule, self::SCHEDULED_HOOK );
	}

	/**
	 * Reschedules when scan_schedule changed.
	 *
	 * @param array $new New settings.
	 * @param array $old Old settings.
	 */
	public function maybe_reschedule( $new, $old ) {
		$new_schedule = isset( $new['scan_schedule'] ) ? $new['scan_schedule'] : '';
		$old_schedule = isset( $old['scan_schedule'] ) ? $old['scan_schedule'] : '';
		if ( $new_schedule !== $old_schedule ) {
			$this->ensure_schedule();
		}
	}

	/**
	 * Manifest keys are paths relative to the scan root, so after the root
	 * changes the old manifest describes nothing. Forget the baseline (and the
	 * queued folder rebaselines) so the next whole-site scan rebuilds it instead
	 * of reporting, or in strict mode quarantining, every file as new.
	 *
	 * @param array $new New settings.
	 * @param array $old Old settings.
	 */
	public function maybe_reset_baseline( $new, $old ) {
		$new_root   = isset( $new['scan_root'] ) ? (string) $new['scan_root'] : 'abspath';
		$old_root   = isset( $old['scan_root'] ) ? (string) $old['scan_root'] : 'abspath';
		$new_custom = isset( $new['scan_root_custom'] ) ? (string) $new['scan_root_custom'] : '';
		$old_custom = isset( $old['scan_root_custom'] ) ? (string) $old['scan_root_custom'] : '';
		if ( $new_root === $old_root && ( 'custom' !== $new_root || $new_custom === $old_custom ) ) {
			return;
		}
		Network::delete_option( Scan_Job::BASELINE_OPTION );
		Network::delete_option( Scan_Job::QUEUE_OPTION );
		wpcybersec()->logger->log(
			'scan_root_changed',
			__( 'The scan folder setting changed. The next full-site scan rebuilds the baseline.', 'qartvelo-guard' ),
			array(
				'old' => 'custom' === $old_root ? $old_custom : $old_root,
				'new' => 'custom' === $new_root ? $new_custom : $new_root,
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Scheduled scan                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Cron entry point: starts an incremental scan and ticks it once. A job
	 * that stopped ticking (its request was killed) is replaced by a new one.
	 */
	public function run_scheduled_scan() {
		if ( ! Network::is_main() ) {
			Network::clear_site_cron(); // An event an older version left on another site of a network.
			return;
		}
		$job = wpcybersec()->scan_job;

		$status = $job->status();
		if ( in_array( $status['state'], array( 'enumerating', 'processing', 'finishing' ), true ) && ! $job->is_stalled() ) {
			// A scan is already running; just keep it moving.
			$this->tick_and_chain();
			return;
		}

		$id = $job->start(
			array(
				'mode'    => 'incremental',
				'malware' => (bool) wpcybersec()->settings->get( 'scan_malware', true ),
				'trigger' => 'cron',
			)
		);
		if ( is_wp_error( $id ) ) {
			wpcybersec()->logger->log(
				'scan_failed',
				/* translators: %s: error message */
				sprintf( __( 'Scheduled scan could not start: %s', 'qartvelo-guard' ), $id->get_error_message() )
			);
			return;
		}
		$this->tick_and_chain();
	}

	/**
	 * One-off tick event: continues a running job and reschedules itself.
	 */
	public function run_tick() {
		$this->tick_and_chain();
	}

	/**
	 * Ticks the job once and, if it is still running, schedules the next tick.
	 */
	private function tick_and_chain() {
		$status = wpcybersec()->scan_job->tick( self::CRON_BUDGET );
		if ( in_array( $status['state'], array( 'enumerating', 'processing', 'finishing' ), true ) ) {
			if ( ! Network::next_scheduled( self::TICK_HOOK ) ) {
				Network::schedule_single( time() + self::TICK_DELAY, self::TICK_HOOK );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Trust helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Marks a file trusted in the manifest (hashing it when no hash is given).
	 *
	 * @param string $abs    Absolute path.
	 * @param string $sha256 Optional known hash.
	 * @return bool
	 */
	public function trust_file( $abs, $sha256 = '' ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs || ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$stat = $this->stat( $abs );
		if ( '' === $sha256 ) {
			$sha256 = Scan_Job::fingerprint( $abs, $stat['size'] );
		}
		wpcybersec()->store->manifest_upsert_many(
			array(
				array(
					'path'   => Paths::rel( $abs ),
					'sha256' => $sha256,
					'size'   => $stat['size'],
					'mtime'  => $stat['mtime'],
					'state'  => Store::STATE_TRUSTED,
					'run_id' => 'trust',
				),
			)
		);
		// Copy of the trusted version, so a later change can be shown line by line.
		$snapshots = wpcybersec()->snapshots;
		if ( $snapshots && '' !== $sha256 ) {
			$snapshots->store( $abs, $sha256 );
		}
		return true;
	}

	/**
	 * Removes a file's manifest row (so it is treated as new again).
	 *
	 * @param string $abs Absolute path.
	 */
	public function forget_file( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs ) {
			return;
		}
		wpcybersec()->store->manifest_delete( array( Paths::hash( Paths::rel( $abs ) ) ) );
	}

	/**
	 * Re-baselines a small set of folders synchronously (after an update of a
	 * plugin, theme or core). Files that verify by checksum or are clean become
	 * trusted; files with malware hits >= high or a checksum mismatch become
	 * threat items and are NOT trusted.
	 *
	 * Files are checked against checksums first (a verified core, plugin or own
	 * file is never signature scanned).
	 *
	 * Never walks the whole site: each folder is capped at REBASELINE_MAX files.
	 * A larger folder keeps its manifest rows and is queued for a background
	 * baseline job (Scan_Job::queue_rebaseline()); until that runs, scans judge
	 * its new and changed files like a baseline instead of reporting them.
	 *
	 * An update only vouches for the files it delivered, and two kinds of
	 * folders are copied over, not replaced, so they can hold files the update
	 * never touched. Those are left as they are for the next scan to judge:
	 *
	 *   - in wp-admin and wp-includes, a file that is not part of WordPress
	 *     (checksums loaded, file not listed): the core updater does not write
	 *     such files;
	 *   - in a folder named in $known_only (the languages folder after a core
	 *     package that carries translations), a file that was not trusted
	 *     before.
	 *
	 * @param array $abs_dirs   Absolute folders.
	 * @param array $known_only Folders among them where only files that were
	 *                          trusted before are trusted again.
	 * @return array { trusted: int, threats: int, skipped: int, queued: int }
	 */
	public function rebaseline_paths( array $abs_dirs, array $known_only = array() ) {
		$strict_dirs = array();
		foreach ( $known_only as $known ) {
			$known_real    = realpath( (string) $known );
			$strict_dirs[] = untrailingslashit( wp_normalize_path( $known_real ? $known_real : (string) $known ) );
		}
		$result  = array( 'trusted' => 0, 'threats' => 0, 'skipped' => 0, 'queued' => 0 );
		$scanner = wpcybersec()->scanner;
		$store   = wpcybersec()->store;
		$root    = Paths::scan_root();
		$malware   = (bool) wpcybersec()->settings->get( 'scan_malware', true );
		$max       = $scanner->max_bytes();
		$snapshots = wpcybersec()->snapshots;

		foreach ( $abs_dirs as $dir ) {
			$dir = wp_normalize_path( (string) $dir );
			if ( '' === $dir ) {
				continue;
			}
			$real = realpath( $dir );
			if ( $real ) {
				$dir = wp_normalize_path( $real );
			}
			if ( ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			// Only rebaseline folders the scan covers (the scan root, or a
			// WordPress folder outside it such as Bedrock's web/app/plugins).
			if ( 0 !== strpos( trailingslashit( $dir ), $root ) && ! Paths::in_full_scope( $dir ) ) {
				continue;
			}

			$files = $this->collect_files( $dir, self::REBASELINE_MAX + 1 );
			if ( count( $files ) > self::REBASELINE_MAX ) {
				// Too large for a synchronous pass: a background baseline job re-trusts it.
				if ( wpcybersec()->scan_job->queue_rebaseline( $dir ) ) {
					++$result['queued'];
				}
				$result['skipped'] += count( $files );
				continue;
			}

			$strict  = in_array( untrailingslashit( $dir ), $strict_dirs, true );
			$upserts = array();
			foreach ( $files as $abs ) {
				$rel  = Paths::rel( $abs );
				$stat = $this->stat( $abs );
				$sha  = Scan_Job::fingerprint( $abs, $stat['size'] );
				if ( '' === $sha ) {
					++$result['skipped'];
					continue;
				}

				$verify    = $scanner->verify_details( $rel, $sha );
				$hits       = array();
				$mismatch   = 'mismatch' === $verify['reason'];
				$executable = Paths::is_executable( $abs );
				if ( 'match' !== $verify['verdict'] && $malware && $stat['size'] <= $max ) {
					$hits = $scanner->scan_file( $abs, $rel );
				}
				$severity = $scanner->max_severity( $hits );

				if ( $severity >= Store::SEV_HIGH || ( $mismatch && Scan_Job::reports_mismatch( $abs, $executable ) ) ) {
					if ( $snapshots ) {
						$snapshots->store( $abs, $sha );
					}
					// Read before the row is replaced: the version trusted before the update is the comparison base.
					$row = $store->manifest_get( $rel );
					$this->record_rebaseline_threat( $abs, $rel, $sha, $stat, $hits, $verify, $row, $executable );
					$store->manifest_upsert_many(
						array(
							array( 'path' => $rel, 'sha256' => $sha, 'size' => $stat['size'], 'mtime' => $stat['mtime'], 'state' => Store::STATE_THREAT, 'run_id' => 'rebaseline' ),
						)
					);
					++$result['threats'];
					continue;
				}

				// Not delivered by this update: the next scan judges it (see the method comment).
				if ( 'match' !== $verify['verdict'] ) {
					if ( 'core' === $verify['source'] && 'unknown_file' === $verify['reason'] ) {
						++$result['skipped'];
						continue;
					}
					if ( $strict ) {
						$row = $store->manifest_get( $rel );
						if ( ! $row || Store::STATE_TRUSTED !== $row['state'] ) {
							++$result['skipped'];
							continue;
						}
					}
				}

				$upserts[] = array(
					'path'   => $rel,
					'sha256' => $sha,
					'size'   => $stat['size'],
					'mtime'  => $stat['mtime'],
					'state'  => Store::STATE_TRUSTED,
					'run_id' => 'rebaseline',
				);
				++$result['trusted'];
				if ( $snapshots && $snapshots->wants( $abs, $stat['size'] ) ) {
					$snapshots->store_trusted( $abs, $sha, $verify );
				}
				if ( count( $upserts ) >= 200 ) {
					$store->manifest_upsert_many( $upserts );
					$upserts = array();
				}
			}
			if ( $upserts ) {
				$store->manifest_upsert_many( $upserts );
			}
		}

		if ( $result['queued'] ) {
			// Starts now when no scan runs; otherwise the running scan starts it when it finishes.
			wpcybersec()->scan_job->start_queued_rebaselines( 0 );
		}

		if ( $result['trusted'] || $result['threats'] ) {
			wpcybersec()->logger->log(
				'rebaseline',
				sprintf(
					/* translators: 1: trusted count, 2: threats count */
					__( 'Re-baselined updated files. Trusted: %1$s, threats: %2$s.', 'qartvelo-guard' ),
					number_format_i18n( $result['trusted'] ),
					number_format_i18n( $result['threats'] )
				),
				$result
			);
		}
		return $result;
	}

	/**
	 * Threat item for a file found during a rebaseline.
	 *
	 * @param string     $abs        Path.
	 * @param string     $rel        Relative path.
	 * @param string     $sha        Hash.
	 * @param array      $stat       Stat.
	 * @param array      $hits       Hits.
	 * @param array      $verify     Checksum result.
	 * @param array|null $row        Manifest row before the rebaseline (null for a file it did not list).
	 * @param bool       $executable Executable name.
	 */
	private function record_rebaseline_threat( $abs, $rel, $sha, array $stat, array $hits, array $verify, $row = null, $executable = true ) {
		$store = wpcybersec()->store;
		if ( $store->item_find_open( Store::TYPE_THREAT, $rel, $sha ) ) {
			return;
		}
		$severity = max( Store::SEV_MEDIUM, wpcybersec()->scanner->max_severity( $hits ) );
		if ( ! $hits && 'mismatch' === $verify['reason'] ) {
			$severity = max( $severity, Store::SEV_MEDIUM );
		}
		// Compared with the version that was trusted before the update (its
		// copy was kept), never with a version still waiting for a decision.
		$details = Scan_Job::base_details(
			array(
				'change' => is_array( $row ) ? 'modified' : 'new',
				'hits'   => array_values( $hits ),
			),
			Scan_Job::approved_base( $rel, $row, $executable ),
			$sha
		);
		if ( '' !== $verify['source'] ) {
			$details['verified'] = $verify['source'];
			if ( '' !== $verify['reason'] ) {
				$details['checksum'] = $verify['reason'];
			}
		}
		$id = $store->item_insert(
			array(
				'type'          => Store::TYPE_THREAT,
				'status'        => Store::STATUS_PENDING,
				'severity'      => $severity,
				'path'          => $rel,
				'original_path' => $abs,
				'sha256'        => $sha,
				'size'          => $stat['size'],
				'mime'          => $this->mime( $abs ),
				'source'        => 'scan',
				'details'       => $details,
			)
		);
		if ( $id ) {
			wpcybersec()->logger->log(
				'threat_found',
				sprintf(
					/* translators: 1: severity, 2: relative path */
					__( '%1$s issue in an updated file: %2$s', 'qartvelo-guard' ),
					Store::severity_label( $severity ),
					$rel
				),
				array( 'item_id' => $id, 'path' => $rel, 'sha256' => $sha )
			);
			$notifier = wpcybersec()->notifier;
			if ( $notifier && method_exists( $notifier, 'item_created' ) ) {
				$notifier->item_created( $id );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Lists files under a folder, stopping once $limit files are collected.
	 * Excluded paths are skipped. Symlinked folders are never walked through
	 * the link (as in Scan_Job): a target inside the scan set is covered at its
	 * real path, so it is not listed here twice. Folders that are their own
	 * entry of the scan set (walked separately) are skipped too.
	 *
	 * @param string $dir   Absolute folder.
	 * @param int    $limit Cap.
	 * @return string[] Absolute paths.
	 */
	private function collect_files( $dir, $limit ) {
		$files = array();
		$stack = array( rtrim( $dir, '/' ) );
		$own   = array();
		foreach ( Paths::scan_set() as $entry ) {
			if ( 'all' === $entry['depth'] ) {
				$own[ $entry['path'] ] = true;
			}
		}
		while ( $stack && count( $files ) < $limit ) {
			$current = array_pop( $stack );
			$dh      = @opendir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			if ( ! $dh ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $dh ) ) ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$abs = $current . '/' . $entry;
				if ( is_link( $abs ) && @is_dir( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
				$rel = Paths::rel( $abs );
				if ( @is_dir( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( ! isset( $own[ trailingslashit( wp_normalize_path( $abs ) ) ] ) && ! Paths::is_excluded( $rel . '/' ) ) {
						$stack[] = $abs;
					}
					continue;
				}
				if ( @is_file( $abs ) && ! Paths::is_excluded( $rel ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$files[] = wp_normalize_path( $abs );
					if ( count( $files ) >= $limit ) {
						break;
					}
				}
			}
			closedir( $dh );
		}
		return $files;
	}

	/**
	 * @param string $abs Path.
	 * @return array { size, mtime }
	 */
	private function stat( $abs ) {
		$size  = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$mtime = @filemtime( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return array(
			'size'  => false === $size ? 0 : (int) $size,
			'mtime' => false === $mtime ? 0 : (int) $mtime,
		);
	}

	/**
	 * @param string $abs Path.
	 * @return string
	 */
	private function mime( $abs ) {
		$type = wp_check_filetype( basename( $abs ) );
		return ! empty( $type['type'] ) ? (string) $type['type'] : '';
	}
}
