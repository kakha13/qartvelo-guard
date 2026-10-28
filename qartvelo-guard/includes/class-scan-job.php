<?php
/**
 * Batched, resumable site scan (one job at a time).
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * A scan runs across many short ticks (AJAX or cron), so a 30k file site never
 * needs a long running request. All state lives in option 'wpcybersec_job'
 * (not autoloaded); the file list is a flat file in <jobs_dir>/<id>.list read
 * back from a stored byte offset.
 *
 * Phases:
 *   enumerating  Iterative DFS, building <id>.list. A whole-site run walks
 *                every folder of Paths::scan_set(): the scan root, the
 *                WordPress folders outside it (listed by absolute path), the
 *                home folder (its own files only) and a wp-config.php above
 *                ABSPATH. Directories are read as a stream; a folder too
 *                large for one tick continues from an entry count next tick
 *                (state 'cursor'), and its rows are never treated as deleted.
 *                A symlinked directory is not walked through the link: when
 *                its target is inside the scan set it is scanned there once,
 *                otherwise it is counted ("symlinked folders not scanned").
 *                Paths::is_excluded folders are skipped.
 *   processing   Batches of ~50 lines: stat, look up the manifest, decide,
 *                hash and malware-scan only when needed, upsert the manifest.
 *                The state is saved after every batch and the deadline is
 *                checked after every file.
 *   finishing    The database scan when the run includes it (Db_Scanner, in
 *                chunks over as many ticks as it needs), then for whole-site
 *                runs the missing core file count and the administrator
 *                check (User_Watch), then deleted-file detection (manifest
 *                rows this run never touched and nobody wrote since it
 *                started), list cleanup, save last_result, log, notify.
 *
 * Concurrency: AJAX, WP-Cron and bin/cron.php can all drive the same job. Only
 * one of them works at a time: tick(), start() and cancel() take the row lock
 * 'wpcybersec_job_lock' (INSERT IGNORE into the options table of the main site, value
 * "<expires>:<token>", taken over atomically once expired). A tick that cannot
 * get the lock returns status() at once. cancel() leaves a request in
 * 'wpcybersec_job_cancel' that the running tick honours at its next batch.
 *
 * List file: one relative path per line; "%", "\r" and "\n" in names are
 * percent-encoded, so a file named with a line break is still one entry. DFS
 * stack entries are rawurlencoded because the state is an option and must be
 * valid UTF-8 even for folder names that are not.
 *
 * Baseline: option 'wpcybersec_baseline_at' (unix time) is set when a
 * whole-site baseline finishes, with 'wpcybersec_manifest_root' (the scan root
 * it was built for). A whole-site incremental or full scan without one, or for
 * another scan root, runs as a baseline instead. Folders too large to
 * re-baseline inline after an update are queued in
 * 'wpcybersec_rebaseline_queue' (relative prefix => microtime when queued):
 * their new and changed files are judged like a baseline until a scan that
 * started after the entry was queued, and covers the folder, finishes.
 *
 * Folders outside the scan root that earlier versions never scanned (option
 * 'wpcybersec_manifest_extra' lists the ones a whole-site run has covered) are
 * adopted like a baseline by the first run that covers them, so an upgrade
 * does not report every file there as new.
 *
 * Crash guard: before a file that needs real work (hash, checksum, signatures)
 * its name goes into <jobs_dir>/<id>.cur, which is emptied when the file is
 * done. A request that dies on the file (fatal error, memory, time limit, a
 * killed worker) leaves the name behind; a file that stopped the scan twice is
 * skipped, reported as "could not be scanned" (a pending file item) and
 * remembered in 'wpcybersec_unscannable' (path hash => size:mtime) so later
 * runs skip it at once until it changes. A shutdown function records the fatal
 * error message and releases the lock.
 */
class Scan_Job {

	const OPTION          = 'wpcybersec_job';
	const LAST_OPTION     = 'wpcybersec_last_scan';
	const BASELINE_OPTION = 'wpcybersec_baseline_at';
	const ROOT_OPTION     = 'wpcybersec_manifest_root';
	const QUEUE_OPTION    = 'wpcybersec_rebaseline_queue';
	const LOCK_OPTION     = 'wpcybersec_job_lock';
	const CANCEL_OPTION   = 'wpcybersec_job_cancel';
	const EXTRA_OPTION    = 'wpcybersec_manifest_extra';
	const SKIP_OPTION     = 'wpcybersec_unscannable';

	/** Times a file may stop the scan before it is skipped. */
	const CRASH_LIMIT = 2;

	/** Files remembered as unscannable. */
	const SKIP_MAX = 200;

	/** Entries of one folder read and sorted at once; a larger folder is streamed (and may span ticks). */
	const DIR_CAP = 20000;

	/** Files listed from one top-level-only folder (the home folder). */
	const TOP_MAX = 5000;

	/** Examples kept in the state for the summary and the log. */
	const EXAMPLES = 5;

	/** WordPress drop-ins (loaded from the top of WP_CONTENT_DIR); never moved to quarantine automatically. */
	const DROPINS = array( 'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php' );

	const BATCH          = 50;
	const ENUM_CHECK     = 200;
	const STALE_SECONDS  = HOUR_IN_SECONDS;
	const DEFAULT_BUDGET = 15.0;

	/** List and stack encoding version stored in the state ('enc'). */
	const ENCODING = 1;

	/** Files larger than this (or max_file_mb when higher) get a partial fingerprint. */
	const HASH_CAP = 268435456;

	/** @var array|null Working copy of the job state for this request. */
	private $state = null;

	/** @var string Lock value held by this request ('' when none). */
	private $lock = '';

	/** @var float Seconds the tick lock is held for (refreshed after each batch). */
	private $lock_hold = 60.0;

	/** @var bool The lock expired and another runner took it over during this tick. */
	private $lost_lock = false;

	/** @var bool The last tick() could not get the lock. */
	private $locked_out = false;

	/** @var bool finish() left queued rebaselines to start after the lock is released. */
	private $chain = false;

	/** @var array|null Rebaseline queue loaded for this tick. */
	private $queue = null;

	/** @var float Last time the cancel request was read from the database. */
	private $cancel_checked = 0.0;

	/** @var int Byte offset after the last line read_lines() consumed. */
	private $read_end = 0;

	/** @var array|null Last checksum verdict: [ rel, sha256, verify_details() result ]. */
	private $verified = null;

	/** @var array|null File that stopped an earlier tick: { rel, attempts, error } (read once per tick). */
	private $crashed = null;

	/** @var string File being worked on now ('' between files), for the shutdown handler. */
	private $inflight = '';

	/** @var int Attempt number of the file being worked on. */
	private $inflight_attempts = 0;

	/** @var bool The shutdown handler is registered for this request. */
	private $shutdown_registered = false;

	/** @var array|null Folders that are their own entry of the scan set (path => true), skipped inside other walks. */
	private $skip_dirs = null;

	/**
	 * Light hooks only; the heavy work is driven by Ajax and File_Monitor.
	 */
	public function register() {}

	/* ------------------------------------------------------------------ */
	/* Lifecycle                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Starts a job. Returns the job id, or a running job's id when one is
	 * active and $opts['force'] is not set.
	 *
	 * @param array $opts mode, malware, paths, trigger, force, wait (seconds to wait for the lock, default 10),
	 *                    database (bool; default: on for full and baseline scans of the whole site,
	 *                    on for scheduled scans when the database was last scanned a day or more
	 *                    ago, off otherwise; never for scans limited to folders).
	 * @return string|\WP_Error
	 */
	public function start( array $opts = array() ) {
		$state = $this->load( true );
		if ( $this->is_active( $state ) && empty( $opts['force'] ) && ! $this->is_stale( $state ) ) {
			return $state['id'];
		}

		$wait = isset( $opts['wait'] ) ? max( 0.0, (float) $opts['wait'] ) : 10.0;
		$lock = $this->acquire_lock( 120, $wait );
		if ( '' === $lock ) {
			$state = $this->load( true );
			if ( $this->is_active( $state ) ) {
				return $state['id'];
			}
			return new \WP_Error( 'wpcybersec_job_busy', __( 'The scanner is busy. Try again in a moment.', 'qartvelo-guard' ) );
		}
		try {
			return $this->start_locked( $opts );
		} finally {
			$this->release_lock( $lock );
		}
	}

	/**
	 * start() body, run while holding the lock.
	 *
	 * @param array $opts Options.
	 * @return string|\WP_Error
	 */
	private function start_locked( array $opts ) {
		$state = $this->load( true );
		if ( $this->is_active( $state ) ) {
			if ( empty( $opts['force'] ) && ! $this->is_stale( $state ) ) {
				return $state['id'];
			}
			$this->cleanup_files( $state );
		}

		$mode = isset( $opts['mode'] ) ? (string) $opts['mode'] : 'incremental';
		if ( ! in_array( $mode, array( 'incremental', 'full', 'baseline' ), true ) ) {
			$mode = 'incremental';
		}

		// The file list lives in the data folder; without a writable one it goes
		// to a private folder in the system temp directory, so scans still run.
		$jobs_dir = $this->jobs_dir_for_run();
		if ( is_wp_error( $jobs_dir ) ) {
			return $jobs_dir;
		}

		$root  = Paths::scan_root();
		$paths = $this->normalize_paths( isset( $opts['paths'] ) ? (array) $opts['paths'] : array() );
		if ( ! empty( $opts['paths'] ) && ! $paths['abs'] ) {
			// Never fall back to the whole site when the requested folders are gone.
			return new \WP_Error( 'wpcybersec_job_paths', __( 'None of the folders to scan exist inside the scan folder.', 'qartvelo-guard' ) );
		}

		// Without a baseline every existing file would be reported as new (and in
		// strict mode moved to quarantine). A whole-site scan therefore builds the
		// baseline first: when none has finished yet, or when the manifest was
		// built for another scan root.
		if ( 'baseline' !== $mode && ! $paths['abs'] && ! $this->has_baseline( $root ) ) {
			$built_for = Network::get_option( self::ROOT_OPTION, '' );
			if ( is_string( $built_for ) && '' !== $built_for && $built_for !== $root ) {
				wpcybersec()->logger->log(
					'scan_root_changed',
					__( 'The scan folder changed since the last baseline, so this scan rebuilds the baseline.', 'qartvelo-guard' ),
					array(
						'old' => $built_for,
						'new' => $root,
					)
				);
			}
			$mode = 'baseline';
		}

		$id   = gmdate( 'YmdHis' ) . substr( md5( uniqid( 'wpcs', true ) ), 0, 8 );
		$list = $jobs_dir['dir'] . '/' . $id . '.list';

		// WordPress folders outside the scan root (whole-site runs only), and
		// the ones no whole-site run has covered yet (adopted like a baseline).
		$scope = $this->scope_for_run( $paths['abs'] ? array() : Paths::extra_roots(), $mode );
		$stack = $paths['stack'];
		foreach ( $scope['extra'] as $entry ) {
			if ( 'all' === $entry['d'] ) {
				$stack[] = rtrim( $entry['p'], '/' );
			}
		}

		$trigger  = isset( $opts['trigger'] ) ? sanitize_key( $opts['trigger'] ) : 'manual';
		$database = false;
		if ( ! $paths['abs'] && wpcybersec()->db_scanner ) {
			if ( isset( $opts['database'] ) && null !== $opts['database'] ) {
				$database = (bool) $opts['database'];
			} elseif ( in_array( $mode, array( 'full', 'baseline' ), true ) ) {
				$database = true;
			} elseif ( 'cron' === $trigger ) {
				$database = $this->db_scan_due();
			}
		}

		$this->state = array(
			'id'           => $id,
			'state'        => 'enumerating',
			'mode'         => $mode,
			'malware'      => isset( $opts['malware'] ) ? (bool) $opts['malware'] : (bool) wpcybersec()->settings->get( 'scan_malware', true ),
			'trigger'      => $trigger,
			// Database scan at the end of this run (Db_Scanner); its cursor while it runs.
			'database'     => $database,
			'db'           => null,
			'db_done'      => false,
			'db_findings'  => 0,
			// Whole-site runs: core files missing (-1 = not known) and new administrators found.
			'missing_core' => -1,
			'new_admins'   => 0,
			'paths'        => $paths['abs'],
			'prefixes'     => $paths['rel'],
			'root'         => $root,
			// Scan set entries outside the root this run walks ({ p, d, k }), the
			// top-level-only folders and single files still to list, the ones
			// adopted like a baseline, and the folders walked on their own.
			'extra'        => $scope['extra'],
			'tops'         => $scope['tops'],
			'adopt'        => $scope['adopt'],
			'skip'         => $scope['skip'],
			// Directory being listed when a tick ran out of time: { d: stack entry, n: entries done }.
			'cursor'       => null,
			'resumed'      => array(),
			'unreadable'   => array(),
			'symlinks'     => 0,
			'symlink_list' => array(),
			'unscannable'  => 0,
			'unscan_list'  => array(),
			'mem_limited'  => 0,
			'enc'          => self::ENCODING,
			// Queued folder rebaselines this run will list from scratch (see settle_rebaseline_queue()).
			'queue_seen'   => $this->rebaseline_queue( true ),
			// Also copy unchanged trusted files that have no stored copy yet (Snapshots).
			'backfill'     => wpcybersec()->snapshots ? wpcybersec()->snapshots->needs_backfill() : false,
			// Backfill generation at the start: a reset during the run (copies
			// deleted, limit raised) keeps the backfill pending for the next scan.
			'backfill_gen' => wpcybersec()->snapshots ? wpcybersec()->snapshots->backfill_generation() : 0,
			'list_file'    => $list,
			// Temp folder holding the list when the data folder is not writable ('' otherwise).
			'tmp_dir'      => $jobs_dir['tmp'] ? $jobs_dir['dir'] : '',
			'list_offset'  => 0,
			'stack'        => array_map( 'rawurlencode', $stack ),
			'enum_count'   => 0,
			'files_total'  => 0,
			'files_done'   => 0,
			'new'          => 0,
			'modified'     => 0,
			'deleted'      => 0,
			'threats'      => 0,
			'new_threats'  => 0,
			'quarantined'  => 0,
			'skipped'      => 0,
			'current'      => '',
			'message'      => '',
			'started_at'   => time(),
			'ticked_at'    => time(),
			'finished_at'  => 0,
		);

		// Start the list file empty. No 0640 chmod: a CLI runner and the web
		// server user must both be able to continue a job when they share a group.
		if ( false === @file_put_contents( $list, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			if ( $jobs_dir['tmp'] ) {
				Fs::rmdir( $jobs_dir['dir'] );
			}
			$this->state = null;
			return new \WP_Error( 'wpcybersec_job_list', __( 'Could not create the scan file list. Check the data folder permissions.', 'qartvelo-guard' ) );
		}
		Fs::chmod( $list, 0660 );

		$this->clear_cancel();
		$this->save();

		if ( $scope['adopt'] ) {
			wpcybersec()->logger->log(
				'scan_scope_added',
				sprintf(
					/* translators: %s: list of folders */
					__( 'This scan also covers WordPress folders outside the scan folder for the first time: %s. Their files are added to the baseline.', 'qartvelo-guard' ),
					implode( ', ', wp_list_pluck( $scope['adopt'], 'p' ) )
				),
				array( 'id' => $id )
			);
		}

		wpcybersec()->logger->log(
			'scan_started',
			sprintf(
				/* translators: 1: scan mode (incremental, full or baseline), 2: what started it (manual, cron, cli) */
				__( 'Scan started: %1$s (%2$s).', 'qartvelo-guard' ),
				$mode,
				$this->state['trigger']
			),
			array(
				'id'      => $id,
				'malware' => $this->state['malware'],
				'paths'   => $this->state['paths'],
			)
		);
		return $id;
	}

	/**
	 * Folder for this run's file list: the data folder's jobs/ folder, or,
	 * when no data folder is writable (Storage::available() false or ensure()
	 * failing), a new random-named folder in get_temp_dir() that the run
	 * deletes when it ends.
	 *
	 * @return array|\WP_Error { dir: string, tmp: bool }
	 */
	private function jobs_dir_for_run() {
		$storage   = wpcybersec()->storage;
		$available = ! method_exists( $storage, 'available' ) || $storage->available();
		$ensured   = $available ? $storage->ensure() : null;
		if ( $available && ! is_wp_error( $ensured ) ) {
			return array(
				'dir' => $storage->jobs_dir(),
				'tmp' => false,
			);
		}
		$tmp = function_exists( 'get_temp_dir' ) ? untrailingslashit( wp_normalize_path( get_temp_dir() ) ) : '';
		if ( '' !== $tmp && @is_dir( $tmp ) && Fs::is_writable( $tmp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$dir = $tmp . '/wpcybersec-jobs-' . strtolower( wp_generate_password( 16, false ) );
			if ( wp_mkdir_p( $dir ) ) {
				Fs::chmod( $dir, 0700 );
				wpcybersec()->logger->log( 'scan_temp_list', __( 'No writable data folder: this scan keeps its file list in the system temp folder. Held files and file copies cannot be stored until the data folder is fixed.', 'qartvelo-guard' ) );
				return array(
					'dir' => $dir,
					'tmp' => true,
				);
			}
		}
		if ( is_wp_error( $ensured ) ) {
			return $ensured;
		}
		$problem = method_exists( $storage, 'problem' ) ? $storage->problem() : array();
		$message = is_array( $problem ) && ! empty( $problem['text'] ) ? $problem['text'] : __( 'No writable data folder, so the scan cannot start.', 'qartvelo-guard' );
		return new \WP_Error( 'wpcybersec_storage', $message );
	}

	/**
	 * Scan set entries outside the root that a run walks.
	 *
	 * @param array[] $entries Paths::extra_roots() (empty for runs limited to folders).
	 * @param string  $mode    Scan mode.
	 * @return array { extra: [{p, d, k}], tops: [{p (rawurlencoded), d}], adopt: [{p, d}], skip: string[] }
	 */
	private function scope_for_run( array $entries, $mode ) {
		$out = array(
			'extra' => array(),
			'tops'  => array(),
			'adopt' => array(),
			'skip'  => array(),
		);
		foreach ( Paths::scan_set() as $entry ) {
			if ( 'all' === $entry['depth'] && Store::db_text( $entry['path'] ) === $entry['path'] ) {
				$out['skip'][] = $entry['path'];
			}
		}
		$known = Network::get_option( self::EXTRA_OPTION, array() );
		$known = is_array( $known ) ? $known : array();
		foreach ( $entries as $entry ) {
			if ( Store::db_text( $entry['path'] ) !== $entry['path'] ) {
				continue; // Not storable in the job state (invalid UTF-8 name).
			}
			$item           = array(
				'p' => $entry['path'],
				'd' => $entry['depth'],
				'k' => $entry['kind'],
			);
			$out['extra'][] = $item;
			if ( 'all' !== $entry['depth'] ) {
				$out['tops'][] = array(
					'p' => rawurlencode( $entry['path'] ),
					'd' => $entry['depth'],
				);
			}
			if ( 'baseline' !== $mode && ! in_array( $entry['path'], $known, true ) ) {
				$out['adopt'][] = array(
					'p' => $entry['path'],
					'd' => $entry['depth'],
				);
			}
		}
		return $out;
	}

	/**
	 * Whether a whole-site baseline exists for the scan root.
	 *
	 * @param string|null $root Scan root (default: the current one).
	 * @return bool
	 */
	public function has_baseline( $root = null ) {
		$root      = null === $root ? Paths::scan_root() : (string) $root;
		$at        = (int) Network::get_option( self::BASELINE_OPTION, 0 );
		$built_for = Network::get_option( self::ROOT_OPTION, false );

		if ( ! $at && false === $built_for ) {
			// Installs from before baseline tracking: a finished whole-site
			// baseline was the last scan (path baselines carry trigger "update").
			$last = $this->last_result();
			if ( isset( $last['mode'], $last['state'], $last['trigger'] ) && 'baseline' === $last['mode'] && 'done' === $last['state'] && 'update' !== $last['trigger'] ) {
				$at = ! empty( $last['finished_at'] ) ? (int) $last['finished_at'] : time();
				Network::update_option( self::BASELINE_OPTION, $at, false );
				Network::update_option( self::ROOT_OPTION, $root, false );
				return true;
			}
			return false;
		}
		if ( ! $at ) {
			return false;
		}
		return ! ( is_string( $built_for ) && '' !== $built_for && $built_for !== $root );
	}

	/**
	 * Does up to $budget_seconds of work and returns the status.
	 *
	 * @param float $budget_seconds Time budget.
	 * @return array status()
	 */
	public function tick( $budget_seconds = self::DEFAULT_BUDGET ) {
		$this->locked_out = false;
		$this->lost_lock  = false;
		$this->chain      = false;

		$budget          = self::clamp_budget( max( 1.0, (float) $budget_seconds ) );
		$this->lock_hold = 2 * $budget + 30;
		$this->lock      = $this->acquire_lock( $this->lock_hold, 0 );
		if ( '' === $this->lock ) {
			// Another runner is working on the job right now; report its progress.
			$this->locked_out = true;
			$this->state      = $this->load( true );
			return $this->status();
		}

		try {
			$status = $this->tick_locked( $budget );
		} finally {
			$this->release_lock( $this->lock );
			$this->lock = '';
		}

		if ( $this->chain ) {
			$this->chain = false;
			$this->start_queued_rebaselines( 2.0 );
		}
		return $status;
	}

	/**
	 * tick() body, run while holding the lock.
	 *
	 * @param float $budget Seconds.
	 * @return array status()
	 */
	private function tick_locked( $budget ) {
		$state = $this->load( true );
		if ( ! $this->is_active( $state ) ) {
			$this->state = $state;
			return $this->status();
		}

		$deadline                 = microtime( true ) + $budget;
		$this->state              = array_merge( self::state_defaults(), $state ); // Jobs started by an older version lack the newer keys.
		$this->state['ticked_at'] = time();
		$this->queue              = null;
		$this->skip_dirs          = null;

		// Large files are read whole for the signatures: ask for the higher
		// admin memory limit where the host allows it (Scanner::read_cap()
		// lowers the read size when memory is still short).
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}
		$this->crashed = $this->read_marker();
		if ( ! $this->shutdown_registered ) {
			$this->shutdown_registered = true;
			register_shutdown_function( array( $this, 'on_shutdown' ) );
			// WordPress' own fatal error handler is a shutdown function that ends
			// with wp_die(), so shutdown functions registered after it never run
			// after a fatal error. It filters the message it is about to show
			// first: record there. (Without that handler, or with a php-error.php
			// drop-in, the shutdown function runs; when nothing runs, the marker
			// written before the file still counts the attempt and the lock
			// expires on its own.)
			add_filter( 'wp_php_error_message', array( $this, 'on_fatal_error' ), 1, 2 );
		}

		try {
			if ( $this->cancel_requested( true ) ) {
				$this->cancel_now();
				return $this->status();
			}
			if ( ! empty( $this->state['root'] ) && $this->state['root'] !== Paths::scan_root() ) {
				$this->fail( __( 'The scan folder setting changed while this scan was running. Start a new scan.', 'qartvelo-guard' ) );
			} else {
				if ( 'enumerating' === $this->state['state'] ) {
					$this->enumerate( $deadline );
				}
				if ( 'processing' === $this->state['state'] && microtime( true ) < $deadline ) {
					$this->process( $deadline );
				}
				if ( 'finishing' === $this->state['state'] && ! $this->lost_lock ) {
					$this->finish( $deadline );
				}
			}
		} catch ( \Throwable $e ) {
			$this->fail( $e->getMessage() );
		}
		$this->inflight = '';

		if ( $this->lost_lock ) {
			// Another runner owns the job now; do not overwrite its state.
			$this->state = null;
			return $this->status();
		}
		if ( $this->state ) {
			$this->save();
		}
		return $this->status();
	}

	/**
	 * Seconds left before max_execution_time ends this request, null when
	 * there is no limit (0, the CLI default).
	 *
	 * @return float|null
	 */
	public static function exec_seconds_left() {
		$max = (int) ini_get( 'max_execution_time' );
		if ( $max <= 0 ) {
			return null;
		}
		$start = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime( true ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- a number set by PHP.
		return max( 0.0, $max - ( microtime( true ) - $start ) );
	}

	/**
	 * A tick never takes more than about half of what max_execution_time has
	 * left (the rest covers the batch that runs over the deadline, the state
	 * save and the database scan step). 0 means no limit.
	 *
	 * @param float $budget Seconds asked for.
	 * @return float
	 */
	public static function clamp_budget( $budget ) {
		$left = self::exec_seconds_left();
		if ( null === $left ) {
			return (float) $budget;
		}
		return max( 1.0, min( (float) $budget, $left / 2 ) );
	}

	/**
	 * Shutdown handler: when the request ends while a file is being worked on
	 * (a fatal error, memory exhausted, max_execution_time), keeps the file
	 * and the error in the crash marker and frees the lock at once, so the
	 * next tick can skip the file after the second time.
	 */
	public function on_shutdown() {
		if ( '' === $this->inflight || ! is_array( $this->state ) ) {
			return;
		}
		$rel            = $this->inflight;
		$this->inflight = ''; // Once: the fatal error filter and the shutdown function both call this.
		$this->inflight_shutdown( $rel );
	}

	/**
	 * 'wp_php_error_message' filter (runs inside WordPress' fatal error
	 * handler, before it ends the request): records the file, changes nothing.
	 *
	 * @param string $message Message WordPress shows.
	 * @param array  $error   error_get_last() result.
	 * @return string
	 */
	public function on_fatal_error( $message, $error = array() ) {
		unset( $error );
		$this->on_shutdown();
		return $message;
	}

	/**
	 * on_shutdown() body.
	 *
	 * @param string $rel File being worked on.
	 */
	private function inflight_shutdown( $rel ) {
		$error   = error_get_last();
		$message = '';
		if ( is_array( $error ) && in_array( (int) $error['type'], array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR ), true ) ) {
			$message = (string) $error['message'];
			// Exhausted memory: a little more lets the handler finish its work.
			if ( false !== stripos( $message, 'memory' ) ) {
				$room = Scanner::memory_room();
				if ( null !== $room && function_exists( 'wp_raise_memory_limit' ) ) {
					// 32 MB above the limit that was just exhausted, through core's
					// wp_raise_memory_limit(), so this handler can record the file.
					$more = (int) wp_convert_hr_to_bytes( (string) ini_get( 'memory_limit' ) ) + 32 * MB_IN_BYTES;
					add_filter(
						'wpcybersec_fatal_memory_limit',
						static function () use ( $more ) {
							return $more;
						}
					);
					wp_raise_memory_limit( 'wpcybersec_fatal' );
				}
			}
		}
		try {
			$this->write_marker( $rel, $this->inflight_attempts, $message );
			if ( '' !== $message && function_exists( 'wpcybersec' ) && wpcybersec()->logger ) {
				wpcybersec()->logger->log(
					'scan_file_stopped',
					sprintf(
						/* translators: 1: relative path, 2: error message */
						__( 'The scan stopped while checking %1$s: %2$s', 'qartvelo-guard' ),
						Store::db_text( $rel ),
						Signatures::clean_snippet( $message )
					),
					array(
						'id'       => isset( $this->state['id'] ) ? $this->state['id'] : '',
						'attempts' => $this->inflight_attempts,
					)
				);
			}
			if ( '' !== $this->lock ) {
				$this->release_lock( $this->lock );
				$this->lock = '';
			}
		} catch ( \Throwable $e ) {
			return; // Nothing more can be done while the request ends.
		}
	}

	/**
	 * Runs ticks until the job is no longer active (CLI and bin/cron.php).
	 * Waits while another runner holds the lock. Stops when the job it started
	 * with is over, even when a queued rebaseline starts right after it.
	 *
	 * @param callable|null $progress Receives status() after each tick.
	 * @return array Final status.
	 */
	public function run_to_completion( $progress = null ) {
		$first  = $this->load( true );
		$id     = $this->is_active( $first ) ? (string) $first['id'] : '';
		$guard  = 100000;
		$status = $this->status();
		do {
			$status = $this->tick( 20.0 );
			if ( is_callable( $progress ) ) {
				call_user_func( $progress, $status );
			}
			if ( $this->locked_out ) {
				usleep( 1000000 );
			}
			$current = $this->load( true );
			$running = $this->is_active( $current ) && ( '' === $id || (string) $current['id'] === $id );
		} while ( $running && --$guard > 0 );

		if ( '' !== $id && ( $status['id'] !== $id || $this->is_active( $status ) ) ) {
			// Another runner finished the job while this one waited for the lock.
			Network::flush_option_cache( self::LAST_OPTION );
			$last = $this->last_result();
			if ( isset( $last['id'] ) && $last['id'] === $id ) {
				return $last;
			}
		}
		return $status;
	}

	/**
	 * Cancels the running job. When a tick is working on it, the tick stops at
	 * its next batch.
	 */
	public function cancel() {
		$state = $this->load( true );
		if ( ! $this->is_active( $state ) ) {
			return;
		}
		$this->request_cancel( (string) $state['id'] );

		$lock = $this->acquire_lock( 60, 8.0 );
		if ( '' === $lock ) {
			return; // The running tick honours the request.
		}
		try {
			$state       = $this->load( true );
			$this->state = $state;
			if ( $this->is_active( $state ) ) {
				$this->cancel_now();
			} else {
				$this->clear_cancel();
			}
		} finally {
			$this->release_lock( $lock );
		}
	}

	/**
	 * Marks the loaded job cancelled (caller holds the lock).
	 */
	private function cancel_now() {
		$this->cleanup_files( $this->state );
		$this->state['state']       = 'cancelled';
		$this->state['current']     = '';
		$this->state['finished_at'] = time();
		$this->state['message']     = __( 'Scan cancelled.', 'qartvelo-guard' );
		$this->save();
		$this->save_last();
		$this->clear_cancel();
		wpcybersec()->logger->log( 'scan_cancelled', __( 'Scan cancelled.', 'qartvelo-guard' ), array( 'id' => $this->state['id'] ) );
	}

	/**
	 * True while a job is active but has not ticked for STALE_SECONDS (its
	 * driver died, for example a request killed by max_execution_time).
	 *
	 * @return bool
	 */
	public function is_stalled() {
		$state = $this->load( true );
		return $this->is_active( $state ) && $this->is_stale( $state );
	}

	/**
	 * Status of the last finished job.
	 *
	 * @return array
	 */
	public function last_result() {
		$last = Network::get_option( self::LAST_OPTION, array() );
		return is_array( $last ) ? $last : array();
	}

	/**
	 * Current job status (safe shape even when idle).
	 *
	 * @return array
	 */
	public function status() {
		$state = null !== $this->state ? $this->state : $this->load();
		if ( ! $state || empty( $state['id'] ) ) {
			return $this->idle_status();
		}
		return array(
			'id'           => (string) $state['id'],
			'state'        => (string) $state['state'],
			'mode'         => (string) $state['mode'],
			'malware'      => (bool) $state['malware'],
			'trigger'      => (string) $state['trigger'],
			'files_total'  => (int) $state['files_total'],
			'files_done'   => (int) $state['files_done'],
			'new'          => (int) $state['new'],
			'modified'     => (int) $state['modified'],
			'deleted'      => (int) $state['deleted'],
			'threats'      => (int) $state['threats'],
			'new_threats'  => isset( $state['new_threats'] ) ? (int) $state['new_threats'] : null,
			'quarantined'  => (int) $state['quarantined'],
			'skipped'      => (int) $state['skipped'],
			'unreadable'   => isset( $state['unreadable'] ) ? count( (array) $state['unreadable'] ) : 0,
			'locked_out'   => ! empty( $this->locked_out ),
			'started_at'   => (int) $state['started_at'],
			'finished_at'  => (int) $state['finished_at'],
			'current'      => (string) $state['current'],
			'message'      => (string) $state['message'],
			'percent'      => $this->percent( $state ),
			'database'     => ! empty( $state['database'] ),
			'db_findings'  => isset( $state['db_findings'] ) ? (int) $state['db_findings'] : 0,
			'missing_core' => isset( $state['missing_core'] ) ? (int) $state['missing_core'] : -1,
			'new_admins'   => isset( $state['new_admins'] ) ? (int) $state['new_admins'] : 0,
			'symlinks'     => isset( $state['symlinks'] ) ? (int) $state['symlinks'] : 0,
			'unscannable'  => isset( $state['unscannable'] ) ? (int) $state['unscannable'] : 0,
			'mem_limited'  => isset( $state['mem_limited'] ) ? (int) $state['mem_limited'] : 0,
			'extra_roots'  => isset( $state['extra'] ) ? count( (array) $state['extra'] ) : 0,
		);
	}

	/**
	 * Values of the state keys newer versions added (merged under the state
	 * of a job an older version started).
	 *
	 * @return array
	 */
	private static function state_defaults() {
		return array(
			'extra'        => array(),
			'tops'         => array(),
			'adopt'        => array(),
			'skip'         => array(),
			'cursor'       => null,
			'resumed'      => array(),
			'unreadable'   => array(),
			'symlinks'     => 0,
			'symlink_list' => array(),
			'unscannable'  => 0,
			'unscan_list'  => array(),
			'mem_limited'  => 0,
			'tmp_dir'      => '',
			'new_threats'  => 0,
		);
	}

	/**
	 * Whether a scheduled scan should include the database (at most once a day).
	 *
	 * @return bool
	 */
	private function db_scan_due() {
		$last = wpcybersec()->db_scanner->last_run();
		$at   = isset( $last['finished_at'] ) ? (int) $last['finished_at'] : 0;
		return $at <= time() - DAY_IN_SECONDS + 10 * MINUTE_IN_SECONDS;
	}

	/* ------------------------------------------------------------------ */
	/* Rebaseline queue (folders too large to re-trust inline)             */
	/* ------------------------------------------------------------------ */

	/**
	 * Queues a folder for a background baseline. Until a scan that listed it
	 * after now finishes, its new and changed files are judged like a baseline
	 * (trusted unless malware) instead of being reported as new.
	 *
	 * @param string $abs_dir Absolute folder inside the scan root, or inside a
	 *                        folder of the scan set outside it (queued by its
	 *                        absolute path, the form its manifest rows use).
	 * @return bool
	 */
	public function queue_rebaseline( $abs_dir ) {
		$root = Paths::scan_root();
		$dir  = trailingslashit( wp_normalize_path( (string) $abs_dir ) );
		if ( 0 === strpos( $dir, $root ) ) {
			if ( $dir === $root ) {
				return false;
			}
			$prefix = substr( $dir, strlen( $root ) );
		} elseif ( Paths::in_full_scope( $dir ) ) {
			$prefix = $dir;
		} else {
			return false;
		}
		if ( Store::db_text( $prefix ) !== $prefix ) {
			return false; // Not storable in an option; the next scan reports it instead.
		}
		$queue            = $this->rebaseline_queue( true );
		$queue[ $prefix ] = microtime( true );
		Network::update_option( self::QUEUE_OPTION, $queue, false );
		$this->queue = null;
		return true;
	}

	/**
	 * Starts a path-limited baseline for the queued folders when no job runs.
	 *
	 * @param float $wait Seconds to wait for the lock.
	 * @return string|false Job id.
	 */
	public function start_queued_rebaselines( $wait = 0.0 ) {
		$queue = $this->rebaseline_queue( true );
		if ( ! $queue ) {
			return false;
		}
		$state = $this->load( true );
		if ( $this->is_active( $state ) && ! $this->is_stale( $state ) ) {
			return false; // That job's finish() starts them.
		}

		$paths   = array();
		$removed = false;
		foreach ( array_keys( $queue ) as $prefix ) {
			$dir = Paths::abs( (string) $prefix );
			if ( @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$paths[] = untrailingslashit( $dir );
			} else {
				unset( $queue[ $prefix ] ); // Folder removed since; its rows go with the next scan.
				$removed = true;
			}
		}
		if ( $removed ) {
			$this->write_queue( $queue );
		}
		if ( ! $paths ) {
			return false;
		}

		$id = $this->start(
			array(
				'mode'    => 'baseline',
				'paths'   => $paths,
				'trigger' => 'update',
				'wait'    => $wait,
			)
		);
		if ( ! is_string( $id ) ) {
			return false;
		}
		if ( function_exists( 'wp_next_scheduled' ) && ! Network::next_scheduled( File_Monitor::TICK_HOOK ) ) {
			Network::schedule_single( time() + 10, File_Monitor::TICK_HOOK );
		}
		return $id;
	}

	/**
	 * @param bool $fresh Bypass the object cache.
	 * @return array Relative prefix => queued at (microtime).
	 */
	private function rebaseline_queue( $fresh = false ) {
		if ( $fresh ) {
			Network::flush_option_cache( self::QUEUE_OPTION );
		}
		$queue = Network::get_option( self::QUEUE_OPTION, array() );
		return is_array( $queue ) ? $queue : array();
	}

	/**
	 * @param array $queue Queue.
	 */
	private function write_queue( array $queue ) {
		if ( $queue ) {
			Network::update_option( self::QUEUE_OPTION, $queue, false );
		} else {
			Network::delete_option( self::QUEUE_OPTION );
		}
		$this->queue = null;
	}

	/**
	 * Whether a relative path lies in a queued folder.
	 *
	 * @param string $rel Relative path.
	 * @return bool
	 */
	private function in_rebaseline_queue( $rel ) {
		if ( null === $this->queue ) {
			$this->queue = $this->rebaseline_queue( true );
		}
		foreach ( $this->queue as $prefix => $queued_at ) {
			if ( '' !== (string) $prefix && 0 === strpos( $rel, (string) $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * At the end of a run: drops queued folders this run fully covered (they
	 * were already queued, with the same time, when it started, so it listed
	 * them after the update; and it scanned the whole site or a parent folder),
	 * and asks tick() to start a baseline for the rest.
	 */
	private function settle_rebaseline_queue() {
		$queue = $this->rebaseline_queue( true );
		if ( ! $queue ) {
			return;
		}
		$seen    = isset( $this->state['queue_seen'] ) && is_array( $this->state['queue_seen'] ) ? $this->state['queue_seen'] : array();
		$covers  = empty( $this->state['paths'] ) ? array( '' ) : (array) $this->state['prefixes'];
		$changed = false;
		foreach ( $queue as $prefix => $queued_at ) {
			if ( ! isset( $seen[ $prefix ] ) || sprintf( '%.6F', (float) $seen[ $prefix ] ) !== sprintf( '%.6F', (float) $queued_at ) ) {
				continue; // Queued (again) after this run started listing files.
			}
			foreach ( $covers as $cover ) {
				if ( '' === (string) $cover || 0 === strpos( (string) $prefix, (string) $cover ) ) {
					unset( $queue[ $prefix ] );
					$changed = true;
					break;
				}
			}
		}
		if ( $changed ) {
			$this->write_queue( $queue );
		}
		if ( $queue ) {
			$this->chain = true;
		}
	}

	/* ------------------------------------------------------------------ */
	/* Phase: enumerating                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Iterative DFS that appends relative file paths to the list file (files
	 * outside the scan root by their absolute path). Directories are read as
	 * a stream, so a folder with a million entries never sits in memory; when
	 * the tick runs out of time inside one, the stack entry and the number of
	 * entries already handled are kept in 'cursor' and the next tick goes on
	 * from there (readdir order is stable for an unchanged folder).
	 *
	 * @param float $deadline Microtime deadline.
	 */
	private function enumerate( $deadline ) {
		$handle = @fopen( $this->state['list_file'], 'ab' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- appended in chunks while the folder tree is walked.
		if ( ! $handle ) {
			$this->fail( __( 'Could not open the scan file list for writing. Check the data folder permissions and that the same user runs every scan step.', 'qartvelo-guard' ) );
			return;
		}

		$checks = 0;
		$buffer = '';

		// Single files and top-level-only folders of the scan set (the home
		// folder, a wp-config.php above ABSPATH): listed once, first.
		while ( ! empty( $this->state['tops'] ) ) {
			$top  = array_shift( $this->state['tops'] );
			$path = rawurldecode( (string) $top['p'] );
			if ( 'file' === $top['d'] ) {
				if ( @is_file( $path ) && ! Paths::is_excluded( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$this->add_line( $handle, $buffer, $path );
				}
				continue;
			}
			$this->list_top( $handle, $buffer, rtrim( $path, '/' ) );
		}

		while ( ! empty( $this->state['stack'] ) ) {
			if ( $this->cancel_requested() ) {
				$this->flush_enum( $handle, $buffer );
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
				$this->cancel_now();
				return;
			}
			$entry   = (string) end( $this->state['stack'] );
			$rel_dir = $this->stack_pop();
			$abs_dir = $this->abs_of( $rel_dir );
			if ( '' === $rel_dir ) {
				$abs_dir = rtrim( $this->root(), '/' );
			}

			// Continue a very large folder an earlier tick stopped inside.
			$skip = -1;
			if ( is_array( $this->state['cursor'] ) && isset( $this->state['cursor']['d'] ) && (string) $this->state['cursor']['d'] === $entry ) {
				$skip = (int) $this->state['cursor']['n'];
			}
			$this->state['cursor'] = null;

			$dh = @opendir( $abs_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			if ( ! $dh ) {
				$this->note_unreadable( $rel_dir, true );
				continue;
			}

			// Usual folders are read whole and handled in name order. Only a
			// folder with more than DIR_CAP entries is streamed, and only such a
			// folder can be continued by a later tick.
			$names = array();
			$huge  = $skip >= 0;
			if ( ! $huge ) {
				while ( false !== ( $name = readdir( $dh ) ) ) {
					if ( '.' === $name || '..' === $name ) {
						continue;
					}
					$names[] = $name;
					if ( count( $names ) > self::DIR_CAP ) {
						$huge = true;
						break;
					}
				}
				if ( ! $huge ) {
					closedir( $dh );
					sort( $names, SORT_STRING );
				}
			}
			$seen = 0;
			foreach ( $names as $name ) {
				++$seen;
				$this->enum_entry( $handle, $buffer, $rel_dir, $abs_dir, $name );
			}
			$names = array();
			if ( $huge ) {
				while ( false !== ( $name = readdir( $dh ) ) ) {
					if ( '.' === $name || '..' === $name ) {
						continue;
					}
					++$seen;
					if ( $seen <= $skip ) {
						continue;
					}
					$this->enum_entry( $handle, $buffer, $rel_dir, $abs_dir, $name );

					if ( ++$checks % self::ENUM_CHECK === 0 && microtime( true ) >= $deadline ) {
						// Put this directory back and go on from here next tick
						// (readdir order is stable while the folder does not change).
						closedir( $dh );
						$this->stack_push( $rel_dir );
						$this->state['cursor'] = array(
							'd' => $entry,
							'n' => $seen,
						);
						if ( count( $this->state['resumed'] ) < 100 && ! in_array( $entry, $this->state['resumed'], true ) ) {
							$this->state['resumed'][] = $entry;
						}
						$this->state['current'] = Store::db_text( $rel_dir );
						$this->flush_enum( $handle, $buffer );
						fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
						return;
					}
				}
				closedir( $dh );
			}

			++$this->state['enum_count'];
			if ( microtime( true ) >= $deadline ) {
				$this->flush_enum( $handle, $buffer );
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
				$this->state['current'] = Store::db_text( $rel_dir );
				return;
			}
		}

		$this->flush_enum( $handle, $buffer );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
		$this->state['state']   = 'processing';
		$this->state['current'] = '';
	}

	/**
	 * Handles one directory entry: a folder goes on the stack, a file into
	 * the list.
	 *
	 * @param resource $handle  Open list file.
	 * @param string   $buffer  Buffered lines.
	 * @param string   $rel_dir Relative (or absolute) folder.
	 * @param string   $abs_dir Absolute folder.
	 * @param string   $name    Entry name.
	 */
	private function enum_entry( $handle, &$buffer, $rel_dir, $abs_dir, $name ) {
		$rel = '' === $rel_dir ? $name : $rel_dir . '/' . $name;
		$abs = $abs_dir . '/' . $name;

		if ( is_link( $abs ) && @is_dir( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			// Never walked through the link (no loops, no file listed twice).
			// When the target is in the scan set it is scanned at its real path
			// (an uploads folder linked to ../files is a folder of the set);
			// anything else is counted so the summary says it was not scanned.
			$real = realpath( $abs );
			if ( ! $real || ! Paths::in_full_scope( wp_normalize_path( $real ) ) ) {
				++$this->state['symlinks'];
				if ( count( $this->state['symlink_list'] ) < self::EXAMPLES ) {
					$this->state['symlink_list'][] = Store::db_text( $rel );
				}
			}
			return;
		}

		if ( @is_dir( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $this->is_own_root( $abs ) || Paths::is_excluded( $rel . '/' ) ) {
				return;
			}
			$this->stack_push( $rel );
			return;
		}

		if ( ! @is_file( $abs ) || Paths::is_excluded( $rel ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return;
		}
		$this->add_line( $handle, $buffer, $rel );
	}

	/**
	 * Lists the files (not the folders) at the top of a folder.
	 *
	 * @param resource $handle Open list file.
	 * @param string   $buffer Buffered lines.
	 * @param string   $dir    Absolute folder without a trailing slash.
	 */
	private function list_top( $handle, &$buffer, $dir ) {
		$dh = @opendir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
		if ( ! $dh ) {
			$this->note_unreadable( $dir, true );
			return;
		}
		$count = 0;
		while ( false !== ( $name = readdir( $dh ) ) ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$abs = $dir . '/' . $name;
			if ( @is_dir( $abs ) || ! @is_file( $abs ) || Paths::is_excluded( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$this->add_line( $handle, $buffer, $abs );
			if ( ++$count >= self::TOP_MAX ) {
				break;
			}
		}
		closedir( $dh );
	}

	/**
	 * @param resource $handle Open list file.
	 * @param string   $buffer Buffered lines.
	 * @param string   $rel    Relative (or absolute) path.
	 */
	private function add_line( $handle, &$buffer, $rel ) {
		$buffer .= $this->encode_line( $rel ) . "\n";
		++$this->state['files_total'];
		if ( strlen( $buffer ) >= 65536 ) {
			$this->flush_enum( $handle, $buffer );
		}
	}

	/**
	 * Whether a folder met inside another walk is an entry of the scan set of
	 * its own (walked separately, with its own keys).
	 *
	 * @param string $abs Absolute folder.
	 * @return bool
	 */
	private function is_own_root( $abs ) {
		if ( null === $this->skip_dirs ) {
			$this->skip_dirs = array();
			$skip            = isset( $this->state['skip'] ) ? (array) $this->state['skip'] : array();
			foreach ( $skip as $dir ) {
				$this->skip_dirs[ (string) $dir ] = true;
			}
		}
		return isset( $this->skip_dirs[ trailingslashit( wp_normalize_path( $abs ) ) ] );
	}

	/**
	 * Absolute path of a list entry or stack entry.
	 *
	 * @param string $rel Relative (or absolute) path.
	 * @return string
	 */
	private function abs_of( $rel ) {
		return Paths::is_absolute( $rel ) ? $rel : $this->root() . $rel;
	}

	/**
	 * @param resource $handle Open list file.
	 * @param string   $buffer Buffered lines (cleared).
	 */
	private function flush_enum( $handle, &$buffer ) {
		if ( '' !== $buffer ) {
			@fwrite( $handle, $buffer ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			$buffer = '';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Phase: processing                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Processes batches of list lines until the deadline or the list ends.
	 * The deadline is checked after every file and the state is saved after
	 * every batch, so one slow file can never make a whole batch repeat.
	 *
	 * @param float $deadline Microtime deadline.
	 */
	private function process( $deadline ) {
		$skiplist = $this->skip_list();

		do {
			if ( $this->cancel_requested() ) {
				$this->cancel_now();
				return;
			}
			$lines = $this->read_lines( self::BATCH );
			if ( false === $lines ) {
				// Never treat an unreadable list as finished: that would delete the
				// manifest rows of every file not reached yet.
				$this->fail( __( 'Could not read the scan file list. Check the data folder permissions and that the same user runs every scan step.', 'qartvelo-guard' ) );
				return;
			}
			if ( ! $lines ) {
				$this->state['list_offset'] = $this->read_end;
				$this->state['state']       = 'finishing';
				return;
			}

			// Look up every path in the manifest in one query.
			$hashes = array();
			foreach ( $lines as $entry ) {
				$hashes[ $entry[0] ] = Paths::hash( $entry[0] );
			}
			$manifest = wpcybersec()->store->manifest_get_many( array_values( $hashes ) );

			$upserts  = array();
			$seen     = array();
			$complete = true;
			$count    = count( $lines );
			foreach ( $lines as $i => $entry ) {
				list( $rel, $end ) = $entry;
				$abs               = $this->abs_of( $rel );
				$stat              = $this->stat( $abs );
				if ( null === $stat ) {
					// Vanished or unreadable between listing and processing.
					if ( @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
						$this->note_unreadable( $rel, false ); // Still there, so its row is kept.
					} else {
						++$this->state['skipped'];
					}
				} else {
					$row = isset( $manifest[ $hashes[ $rel ] ] ) ? $manifest[ $hashes[ $rel ] ] : null;

					// Crash guard: a file that stopped the scan CRASH_LIMIT times
					// (or did so in an earlier run and has not changed since) is
					// reported as "could not be scanned" instead of being retried.
					$stamp    = $stat['size'] . ':' . $stat['mtime'];
					$attempts = 1;
					$light    = is_array( $row ) && Store::STATE_TRUSTED === (string) $row['state'] && (int) $row['size'] === $stat['size'] && (int) $row['mtime'] === $stat['mtime'] && '' !== (string) $row['sha256'] && 'full' !== $this->state['mode'];
					if ( isset( $skiplist[ $hashes[ $rel ] ] ) && $skiplist[ $hashes[ $rel ] ] === $stamp ) {
						$result = $this->unscannable( $abs, $rel, $stat, $row, '', false );
					} elseif ( is_array( $this->crashed ) && $this->crashed['rel'] === $rel && $this->crashed['attempts'] >= self::CRASH_LIMIT ) {
						$result        = $this->unscannable( $abs, $rel, $stat, $row, (string) $this->crashed['error'], true );
						$this->crashed = null;
						$this->write_marker( '', 0 );
					} else {
						if ( is_array( $this->crashed ) && $this->crashed['rel'] === $rel ) {
							$attempts = (int) $this->crashed['attempts'] + 1;
						}
						if ( ! $light ) {
							// Unchanged trusted files only take the cheap path: no marker.
							$this->inflight          = $rel;
							$this->inflight_attempts = $attempts;
							$this->write_marker( $rel, $attempts );
						}
						$result = $this->evaluate( $abs, $rel, $stat, $row );
						$this->capture( $abs, $rel, $stat, $row, $result );
						if ( ! $light ) {
							$this->inflight = '';
							$this->write_marker( '', 0 );
							if ( $attempts > 1 ) {
								$this->crashed = null;
							}
						}
					}

					// A file that was flagged and now verifies (official checksum or
					// approved fingerprint) no longer needs a decision.
					if ( $row && Store::STATE_TRUSTED !== (string) $row['state'] && Store::STATE_TRUSTED === $result['state'] ) {
						wpcybersec()->store->items_resolve_open( $rel, 'now_trusted' );
					}

					$upserts[] = array(
						'path'   => $rel,
						'sha256' => $result['sha256'],
						'size'   => $stat['size'],
						'mtime'  => $stat['mtime'],
						'state'  => $result['state'],
						'run_id' => $this->state['id'],
					);
					$seen[]                 = $hashes[ $rel ];
					$this->state['current'] = Store::db_text( $rel );
				}
				++$this->state['files_done'];
				$this->state['list_offset'] = $end;

				if ( $i < $count - 1 && microtime( true ) >= $deadline ) {
					$complete = false;
					break;
				}
			}
			if ( $complete ) {
				$this->state['list_offset'] = $this->read_end;
			}

			if ( $upserts ) {
				wpcybersec()->store->manifest_upsert_many( $upserts );
			}
			if ( $seen ) {
				// Mark pre-existing rows (unchanged, skipped) as seen this run too.
				wpcybersec()->store->manifest_touch( $seen, $this->state['id'] );
			}

			if ( ! $this->refresh_lock() ) {
				$this->lost_lock = true;
				return;
			}
			$this->save();
		} while ( microtime( true ) < $deadline );
	}

	/**
	 * Decides what a single file is and records items as needed.
	 *
	 * Order in every mode: the allowlist, then official checksums (a verified
	 * core, plugin or own file is never signature scanned), then malware
	 * signatures, then the file policy.
	 *
	 * @param string     $abs  Absolute path.
	 * @param string     $rel  Relative path.
	 * @param array      $stat { size, mtime }.
	 * @param array|null $row  Manifest row or null.
	 * @return array { state, sha256 }
	 */
	private function evaluate( $abs, $rel, array $stat, $row ) {
		$scanner = wpcybersec()->scanner;
		$mode    = $this->state['mode'];
		$malware = $this->state['malware'];

		$known     = is_array( $row );
		$unchanged = $known && (int) $row['size'] === $stat['size'] && (int) $row['mtime'] === $stat['mtime'] && '' !== (string) $row['sha256'];

		// Where a file is can be wrong by itself (a file among the core files that
		// WordPress does not ship, a stray PHP file in the WordPress root). This
		// only looks at the path and the core file list, so it runs for unchanged
		// trusted files too: a baseline from before this check cannot hide them.
		$integrity = $scanner->integrity_issue( $rel );
		if ( '' !== $integrity && $unchanged && wpcybersec()->allowlist->is_allowed_hash( (string) $row['sha256'], Paths::is_executable( $abs ) ) ) {
			$integrity = ''; // Approved before ("Mark safe" or "Allow").
		}

		// Fast path: unchanged + already trusted. Incremental and baseline skip it;
		// full re-scans trusted files for malware using the stored hash.
		if ( $unchanged && Store::STATE_TRUSTED === (string) $row['state'] && 'full' !== $mode && '' === $integrity ) {
			++$this->state['skipped'];
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => (string) $row['sha256'],
			);
		}

		$prev_sha = $known ? (string) $row['sha256'] : '';
		$sha      = $unchanged ? $prev_sha : $this->hash( $abs, $stat['size'] );
		if ( '' === $sha ) {
			// Could not read the file; keep going without changing its state.
			++$this->state['skipped'];
			return array(
				'state'  => $known ? (string) $row['state'] : Store::STATE_PENDING,
				'sha256' => $prev_sha,
			);
		}

		// A row without a fingerprint (the file could not be read or scanned
		// before) was never judged: its content is judged like a new file.
		$is_new     = ! $known || '' === $prev_sha;
		$changed    = $known && ! $unchanged && '' !== $prev_sha && ! hash_equals( $prev_sha, $sha );
		$too_big    = $stat['size'] > $scanner->max_bytes();
		$executable = Paths::is_executable( $abs );
		$change     = $is_new ? 'new' : 'modified';
		// An approval covers the kind of name it was given for: bytes approved as
		// an image are not approved as a PHP file.
		$allowed = wpcybersec()->allowlist->is_allowed_hash( $sha, $executable );

		/* -------- Baseline (or a folder re-baselined after an update, or a folder
		   outside the scan root covered for the first time). -------- */
		if ( 'baseline' === $mode || ( ! $unchanged && ( $this->in_rebaseline_queue( $rel ) || $this->in_adopted( $rel ) ) ) ) {
			return $this->evaluate_baseline( $abs, $rel, $sha, $stat, $row, $change, $executable, $allowed, $too_big, $integrity, $changed );
		}

		/* -------- Nothing to decide: known, unchanged, not trusted, no full re-scan.
		   This only happens for files already pending/threat that have not changed
		   (and trusted files with a path problem, which are judged below). */
		if ( $unchanged && 'full' !== $mode && ( '' === $integrity || Store::STATE_TRUSTED !== (string) $row['state'] ) ) {
			++$this->state['skipped'];
			return array(
				'state'  => (string) $row['state'],
				'sha256' => $sha,
			);
		}

		if ( $allowed ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}

		// Official checksums: a verified file is trusted without a malware scan.
		$verify = $this->verify( $rel, $sha );
		if ( 'match' === $verify['verdict'] ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}

		// An empty or comments-only PHP file (the classic "Silence is golden"
		// index.php that blocks folder listings) cannot run any code.
		if ( $executable && $scanner->is_inert_php( $abs, $stat['size'] ) ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}

		if ( '' !== $integrity ) {
			$hits = $malware && ! $too_big ? $this->scan_content( $abs, $rel ) : array();
			return $this->handle_integrity( $integrity, $abs, $rel, $sha, $stat, $row, $hits, $verify, $is_new, $changed, $executable, false );
		}

		// What a report is compared with: the last version that was approved,
		// never a version that is itself still waiting for a decision.
		$base = self::approved_base( $rel, $row, $executable );

		// Malware scan (skipped for unchanged files unless mode is full).
		$hits     = array();
		$scan_now = $malware && ! $too_big && ( $is_new || $changed || 'full' === $mode );
		if ( $scan_now ) {
			$hits = $this->scan_content( $abs, $rel );
		}
		$severity = $scanner->max_severity( $hits );

		if ( $severity >= Store::SEV_HIGH ) {
			if ( $is_new ) {
				++$this->state['new'];
			} elseif ( $changed ) {
				++$this->state['modified'];
			}
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, $base, $verify );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}

		// A checksum mismatch on a core, wordpress.org plugin or own file is
		// suspicious even with no signature hit: record a medium threat so the
		// admin can review it (scripts, server config and JavaScript; not
		// images, styles or translations).
		if ( 'mismatch' === $verify['reason'] && self::reports_mismatch( $abs, $executable ) ) {
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, $base, $verify, Store::SEV_MEDIUM );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}

		// Low severity signature hits (medium) on executable files -> pending file item.
		if ( $severity >= Store::SEV_MEDIUM && $executable ) {
			if ( $is_new ) {
				++$this->state['new'];
			} elseif ( $changed ) {
				++$this->state['modified'];
			}
			$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
			return array(
				'state'  => Store::STATE_PENDING,
				'sha256' => $sha,
			);
		}

		// A full re-scan only adds findings: a file still waiting for a decision
		// is never promoted to trusted (that would also put it on the fapolicyd
		// trust export).
		if ( $unchanged && Store::STATE_TRUSTED !== (string) $row['state'] ) {
			return array(
				'state'  => (string) $row['state'],
				'sha256' => $sha,
			);
		}

		// New or modified executable files with no hit: apply the file policy.
		if ( $executable ) {
			if ( $is_new ) {
				return $this->handle_new_executable( $abs, $rel, $sha, $stat, $verify );
			}
			if ( $changed ) {
				return $this->handle_modified_executable( $abs, $rel, $sha, $stat, $base, $verify );
			}
		}

		// New or changed non-executable file: nothing to hold, just record the state.
		if ( $is_new ) {
			++$this->state['new'];
		} elseif ( $changed ) {
			++$this->state['modified'];
		}
		return array(
			'state'  => Store::STATE_TRUSTED,
			'sha256' => $sha,
		);
	}

	/**
	 * Baseline decision: trusted, except malware hits and tampered files of
	 * this plugin itself.
	 *
	 * @param string $abs        Path.
	 * @param string $rel        Relative path.
	 * @param string     $sha        Hash.
	 * @param array      $stat       Stat.
	 * @param array|null $row        Manifest row before this run.
	 * @param string     $change     new | modified.
	 * @param bool       $executable Executable name.
	 * @param bool       $allowed    Allowlisted for this kind of name.
	 * @param bool       $too_big    Larger than max_file_mb.
	 * @param string     $integrity  Scanner::integrity_issue() result.
	 * @param bool       $changed    Content differs from the manifest row.
	 * @return array { state, sha256 }
	 */
	private function evaluate_baseline( $abs, $rel, $sha, array $stat, $row, $change, $executable, $allowed, $too_big, $integrity = '', $changed = false ) {
		$trusted = array(
			'state'  => Store::STATE_TRUSTED,
			'sha256' => $sha,
		);
		if ( $allowed ) {
			return $trusted;
		}

		// Checksums first: a verified core, plugin or own file is never signature
		// scanned (this plugin's signature file holds the patterns as data).
		$scanner = wpcybersec()->scanner;
		$verify  = $this->verify( $rel, $sha );
		if ( 'match' === $verify['verdict'] ) {
			return $trusted;
		}
		if ( $executable && $scanner->is_inert_php( $abs, $stat['size'] ) ) {
			return $trusted;
		}

		$hits = array();
		if ( $this->state['malware'] && ! $too_big ) {
			$hits = $this->scan_content( $abs, $rel );
		}
		// A baseline trusts what is there, except files that are wrong by where
		// they are (unknown file in wp-admin or wp-includes, stray root PHP file).
		if ( '' !== $integrity ) {
			return $this->handle_integrity( $integrity, $abs, $rel, $sha, $stat, $row, $hits, $verify, ! is_array( $row ), $changed, $executable, true );
		}
		if ( $hits ) {
			if ( $scanner->max_severity( $hits ) >= Store::SEV_HIGH ) {
				$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, self::approved_base( $rel, $row, $executable ), $verify );
				return array(
					'state'  => Store::STATE_THREAT,
					'sha256' => $sha,
				);
			}
		}

		// A core, wordpress.org plugin or own file that differs from its official
		// checksum is never trusted silently, not even by a baseline: the
		// Changes view compares it with the official original (Originals).
		// Checksums unavailable (offline) means no verdict, so nothing is said.
		if ( 'mismatch' === $verify['reason'] && in_array( $verify['source'], array( 'core', 'plugin', 'self' ), true ) && self::reports_mismatch( $abs, $executable ) ) {
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, self::approved_base( $rel, $row, $executable ), $verify, Store::SEV_MEDIUM );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}
		return $trusted;
	}

	/**
	 * Scanner::scan_file(), counting files whose content was not read because
	 * the memory left was too small (Scanner::read_cap()).
	 *
	 * @param string $abs Path.
	 * @param string $rel Relative path.
	 * @return array[] Hits.
	 */
	private function scan_content( $abs, $rel ) {
		$scanner = wpcybersec()->scanner;
		$hits    = $scanner->scan_file( $abs, $rel );
		if ( $scanner->memory_limited() ) {
			++$this->state['mem_limited'];
		}
		return $hits;
	}

	/**
	 * Whether a path lies in a folder outside the scan root that this run
	 * covers for the first time (judged like a baseline).
	 *
	 * @param string $rel Relative (absolute for these folders) path.
	 * @return bool
	 */
	private function in_adopted( $rel ) {
		if ( empty( $this->state['adopt'] ) || ! Paths::is_absolute( $rel ) ) {
			return false;
		}
		foreach ( (array) $this->state['adopt'] as $entry ) {
			$path = (string) $entry['p'];
			if ( 'all' === $entry['d'] && 0 === strpos( $rel, $path ) ) {
				return true;
			}
			if ( 'top' === $entry['d'] && trailingslashit( wp_normalize_path( dirname( $rel ) ) ) === $path ) {
				return true;
			}
			if ( 'file' === $entry['d'] && $rel === $path ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A file that stopped the scan CRASH_LIMIT times (or is remembered as
	 * such and unchanged): never read again, reported as a pending file item
	 * "could not be scanned" (deduplicated like every item), and remembered
	 * so later runs skip it at once until it changes.
	 *
	 * @param string     $abs      Path.
	 * @param string     $rel      Relative path.
	 * @param array      $stat     Stat.
	 * @param array|null $row      Manifest row.
	 * @param string     $error    Last fatal error message ('' when unknown).
	 * @param bool       $remember Add it to the skip list.
	 * @return array { state, sha256 }
	 */
	private function unscannable( $abs, $rel, array $stat, $row, $error, $remember ) {
		++$this->state['unscannable'];
		if ( count( $this->state['unscan_list'] ) < self::EXAMPLES ) {
			$this->state['unscan_list'][] = Store::db_text( $rel );
		}
		// The previous fingerprint only (hashing the file again could be what stops the scan).
		$sha = is_array( $row ) ? (string) $row['sha256'] : '';
		if ( $remember ) {
			$this->remember_unscannable( $rel, $stat );
			wpcybersec()->logger->log(
				'scan_file_unscannable',
				sprintf(
					/* translators: 1: relative path, 2: number of attempts */
					__( 'Skipped %1$s: the scan stopped on this file %2$s times. It is reported as not scanned.', 'qartvelo-guard' ),
					Store::db_text( $rel ),
					number_format_i18n( self::CRASH_LIMIT )
				),
				array(
					'id'    => $this->state['id'],
					'path'  => Store::db_text( $rel ),
					'error' => Signatures::clean_snippet( $error ),
				)
			);
		}
		$store = wpcybersec()->store;
		if ( ! $store->item_find_open( Store::TYPE_FILE, $rel, $sha ) ) {
			$hit = array(
				'sig'      => 'scan_stopped',
				'title'    => __( 'Could not be scanned: the scan stopped on this file (fatal error, memory or time limit)', 'qartvelo-guard' ),
				'severity' => Store::SEV_MEDIUM,
				'line'     => 0,
				'snippet'  => Signatures::clean_snippet( '' !== $error ? $error : $rel ),
			);
			$id  = $store->item_insert(
				array(
					'type'          => Store::TYPE_FILE,
					'status'        => Store::STATUS_PENDING,
					'severity'      => Store::SEV_MEDIUM,
					'path'          => $rel,
					'original_path' => $abs,
					'sha256'        => $sha,
					'size'          => $stat['size'],
					'mime'          => $this->mime( $abs ),
					'source'        => 'scan',
					'details'       => array(
						'change'  => is_array( $row ) ? 'modified' : 'new',
						'hits'    => array( $hit ),
						'context' => 'scan_stopped',
					),
				)
			);
			if ( $id ) {
				$this->notify_item( $id );
			}
		}
		return array(
			'state'  => is_array( $row ) && Store::STATE_THREAT === (string) $row['state'] ? Store::STATE_THREAT : Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * @return array path hash => "size:mtime" of files remembered as unscannable.
	 */
	private function skip_list() {
		$list = Network::get_option( self::SKIP_OPTION, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * @param string $rel  Relative path.
	 * @param array  $stat Stat.
	 */
	private function remember_unscannable( $rel, array $stat ) {
		$list                       = $this->skip_list();
		$list[ Paths::hash( $rel ) ] = $stat['size'] . ':' . $stat['mtime'];
		if ( count( $list ) > self::SKIP_MAX ) {
			$list = array_slice( $list, -self::SKIP_MAX, null, true );
		}
		Network::update_option( self::SKIP_OPTION, $list, false );
	}

	/**
	 * Crash marker of the running job.
	 *
	 * @return string Path ('' when there is no job).
	 */
	private function marker_file() {
		if ( empty( $this->state['list_file'] ) ) {
			return '';
		}
		return preg_replace( '~\.list$~', '.cur', (string) $this->state['list_file'] );
	}

	/**
	 * Records the file being worked on ('' clears it).
	 *
	 * @param string $rel      Relative path.
	 * @param int    $attempts Attempt number.
	 * @param string $error    Fatal error message.
	 */
	private function write_marker( $rel, $attempts, $error = '' ) {
		$file = $this->marker_file();
		if ( '' === $file ) {
			return;
		}
		$data = '' === $rel ? '' : "v1\n" . rawurlencode( $rel ) . "\n" . (int) $attempts . "\n" . str_replace( array( "\r", "\n" ), ' ', substr( (string) $error, 0, 500 ) );
		@file_put_contents( $file, $data ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- a few bytes before and after each file; must work in a shutdown handler.
	}

	/**
	 * The file a previous tick was working on when its request ended.
	 *
	 * @return array|null { rel, attempts, error }
	 */
	private function read_marker() {
		$file = $this->marker_file();
		if ( '' === $file || ! @is_file( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		$data = (string) @file_get_contents( $file, false, null, 0, 8192 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$part = explode( "\n", $data, 4 );
		if ( count( $part ) < 3 || 'v1' !== $part[0] || '' === $part[1] ) {
			return null;
		}
		return array(
			'rel'      => rawurldecode( $part[1] ),
			'attempts' => max( 1, (int) $part[2] ),
			'error'    => isset( $part[3] ) ? (string) $part[3] : '',
		);
	}

	/**
	 * Which files a checksum mismatch is reported for: executable names
	 * (PHP, .htaccess, .user.ini...) and JavaScript, a common injection target.
	 * Images, styles, fonts and translations that differ are not reported.
	 *
	 * @param string $abs        Path.
	 * @param bool   $executable Executable name.
	 * @return bool
	 */
	public static function reports_mismatch( $abs, $executable ) {
		return (bool) $executable || in_array( Paths::ext( (string) $abs ), array( 'js', 'mjs' ), true );
	}

	/**
	 * Scanner::verify_details() with the last result remembered, so capture()
	 * does not verify the file evaluate() just verified again.
	 *
	 * @param string $rel Relative path.
	 * @param string $sha Hash.
	 * @return array
	 */
	private function verify( $rel, $sha ) {
		if ( null !== $this->verified && $this->verified[0] === $rel && $this->verified[1] === $sha ) {
			return $this->verified[2];
		}
		$result         = wpcybersec()->scanner->verify_details( $rel, $sha );
		$this->verified = array( $rel, $sha, $result );
		return $result;
	}

	/**
	 * Keeps a copy of a file this run trusts (Snapshots), so a later change can
	 * be shown line by line. Files that were already trusted with the same
	 * content got their copy back then; they are only copied again while the
	 * one-time backfill runs (copies were just switched on). Files that match an
	 * official WordPress.org checksum are not copied.
	 *
	 * @param string     $abs    Path.
	 * @param string     $rel    Relative path.
	 * @param array      $stat   Stat.
	 * @param array|null $row    Manifest row before this run.
	 * @param array      $result evaluate() result.
	 */
	private function capture( $abs, $rel, array $stat, $row, array $result ) {
		if ( Store::STATE_TRUSTED !== $result['state'] || '' === (string) $result['sha256'] ) {
			return;
		}
		$known = is_array( $row ) && Store::STATE_TRUSTED === (string) $row['state'] && hash_equals( (string) $row['sha256'], (string) $result['sha256'] );
		if ( $known && empty( $this->state['backfill'] ) ) {
			return;
		}
		$snapshots = wpcybersec()->snapshots;
		if ( ! $snapshots || ! $snapshots->wants( $abs, $stat['size'] ) ) {
			return;
		}
		// An existing copy is not read again, only kept from the next prune().
		$snapshots->store_trusted( $abs, $result['sha256'], $this->verify( $rel, (string) $result['sha256'] ) );
	}

	/**
	 * Keeps a copy of a reported file as it is now, before it may be moved to
	 * quarantine (the previous version is the copy taken when it was trusted).
	 *
	 * @param string $abs Path.
	 * @param string $sha Hash.
	 */
	private function snapshot_current( $abs, $sha ) {
		$snapshots = wpcybersec()->snapshots;
		if ( $snapshots && '' !== (string) $sha ) {
			$snapshots->store( $abs, $sha );
		}
	}

	/**
	 * Files WordPress or a cache plugin writes and loads, which are never
	 * moved to quarantine automatically (they are still reported):
	 *   dropin     a drop-in name at the top of WP_CONTENT_DIR
	 *              (advanced-cache.php, object-cache.php, db.php, sunrise.php...);
	 *   generated  wp-content/cache/, wp-content/litespeed/,
	 *              wp-content/wp-rocket-config/, wp-content/w3tc-config/ and
	 *              wp-content/wp-cache-config.php (page and object caches and
	 *              their settings, rewritten by the plugin).
	 *
	 * @param string $abs Absolute path.
	 * @return string dropin | generated | ''
	 */
	public static function generated_kind( $abs ) {
		static $roots = null;
		if ( null === $roots ) {
			$roots = array();
			foreach ( array( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '', ABSPATH . 'wp-content' ) as $dir ) {
				if ( '' === $dir ) {
					continue;
				}
				$roots[] = trailingslashit( wp_normalize_path( $dir ) );
				$real    = realpath( $dir );
				if ( $real ) {
					$roots[] = trailingslashit( wp_normalize_path( $real ) );
				}
			}
			$roots = array_values( array_unique( $roots ) );
		}
		$abs = wp_normalize_path( (string) $abs );
		foreach ( $roots as $root ) {
			if ( 0 !== strpos( $abs, $root ) ) {
				continue;
			}
			$sub = substr( $abs, strlen( $root ) );
			if ( false === strpos( $sub, '/' ) ) {
				$names = self::DROPINS;
				if ( function_exists( '_get_dropins' ) ) {
					$names = array_merge( $names, array_keys( (array) _get_dropins() ) );
				}
				if ( in_array( strtolower( $sub ), $names, true ) ) {
					return 'dropin';
				}
				return 'wp-cache-config.php' === strtolower( $sub ) ? 'generated' : '';
			}
			if ( preg_match( '~^(?:cache|litespeed|wp-rocket-config|w3tc-config)/~i', $sub ) ) {
				return 'generated';
			}
			return '';
		}
		return '';
	}

	/**
	 * True for a file that belongs to this plugin's own code (listed in
	 * checksums.json, or checksums.json is missing). Such files are never moved
	 * to quarantine: that would break the security plugin itself.
	 *
	 * @param array|null $verify verify_details() result.
	 * @return bool
	 */
	private function is_own_code( $verify ) {
		return is_array( $verify ) && 'self' === $verify['source'] && 'unknown_file' !== $verify['reason'];
	}

	/**
	 * New executable file with no malware hit.
	 *
	 * @param string     $abs    Path.
	 * @param string     $rel    Relative path.
	 * @param string     $sha    Hash.
	 * @param array      $stat   Stat.
	 * @param array|null $verify Checksum result.
	 * @return array
	 */
	private function handle_new_executable( $abs, $rel, $sha, array $stat, $verify = null ) {
		++$this->state['new'];
		$mode = (string) wpcybersec()->settings->get( 'file_mode', 'report' );
		if ( 'off' === $mode ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}
		if ( 'quarantine_exec' === $mode && ! $this->is_own_code( $verify ) ) {
			return $this->quarantine_file( $abs, $rel, $sha, $stat, 'new', self::no_base() );
		}
		$this->record_file( $abs, $rel, $sha, $stat, 'new', self::no_base(), array() );
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * Modified executable file with no malware hit.
	 *
	 * @param string     $abs      Path.
	 * @param string     $rel      Relative path.
	 * @param string     $sha      Hash.
	 * @param array      $stat     Stat.
	 * @param array      $base     approved_base().
	 * @param array|null $verify   Checksum result.
	 * @return array
	 */
	private function handle_modified_executable( $abs, $rel, $sha, array $stat, array $base, $verify = null ) {
		++$this->state['modified'];
		$action = (string) wpcybersec()->settings->get( 'modified_action', 'report' );
		if ( 'quarantine' === $action && ! $this->is_own_code( $verify ) ) {
			return $this->quarantine_file( $abs, $rel, $sha, $stat, 'modified', $base );
		}
		$this->record_file( $abs, $rel, $sha, $stat, 'modified', $base, array() );
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * Moves a file to quarantine and records a pending file item with the held
	 * copy (the admin approves, which restores it, or deletes it).
	 *
	 * @param string $abs      Path.
	 * @param string $rel      Relative path.
	 * @param string $sha      Hash.
	 * @param array  $stat     Stat.
	 * @param string $change   new | modified.
	 * @param array  $base     approved_base().
	 * @param array  $hits     Hits that explain the report.
	 * @return array
	 */
	private function quarantine_file( $abs, $rel, $sha, array $stat, $change, array $base, array $hits = array() ) {
		$this->snapshot_current( $abs, $sha );
		// A file the site needs to start (wp-config.php, core files) is only ever reported.
		// Nor are drop-ins and files cache plugins write (advanced-cache.php,
		// object-cache.php, wp-content/cache/...): moving them breaks the site
		// or the plugin writes them again at once. They are still reported.
		$held = Decisions::is_critical_path( $abs ) || '' !== self::generated_kind( $abs ) ? new \WP_Error( 'wpcybersec_critical', 'critical' ) : wpcybersec()->quarantine->hold( $abs, true );
		if ( is_wp_error( $held ) ) {
			// Could not move it; fall back to reporting it in place.
			$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
			return array(
				'state'  => Store::STATE_PENDING,
				'sha256' => $sha,
			);
		}
		++$this->state['quarantined'];
		// Status stays pending: the item still needs a decision and must show in
		// Pending approvals, counts, and the scan email.
		$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits, $held['quarantine_path'], Store::STATUS_PENDING );
		wpcybersec()->logger->log(
			'file_quarantined',
			/* translators: %s: relative path */
			sprintf( __( 'Quarantined new executable file %s.', 'qartvelo-guard' ), $rel ),
			array( 'path' => $rel, 'sha256' => $sha )
		);
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * A file that is wrong by where it is (Scanner::integrity_issue()), in
	 * every scan mode including baseline:
	 *   core_unknown_file  -> high threat (more when signatures say so);
	 *   root_php,
	 *   core_unknown_config -> medium pending file item, or a threat when a
	 *                          signature found high severity code. A new or
	 *                          changed file outside a baseline follows the
	 *                          quarantine policy for new and modified files.
	 * Deduplicated like every other item (open item for the same path + hash).
	 *
	 * @param string     $integrity  Issue code.
	 * @param string     $abs        Path.
	 * @param string     $rel        Relative path.
	 * @param string     $sha        Hash.
	 * @param array      $stat       Stat.
	 * @param array|null $row        Manifest row before this run.
	 * @param array      $hits       Signature hits.
	 * @param array      $verify     Checksum result.
	 * @param bool       $is_new     Not in the manifest before.
	 * @param bool       $changed    Content changed since the manifest row.
	 * @param bool       $executable Executable name.
	 * @param bool       $baseline   Judged as part of a baseline.
	 * @return array { state, sha256 }
	 */
	private function handle_integrity( $integrity, $abs, $rel, $sha, array $stat, $row, array $hits, $verify, $is_new, $changed, $executable, $baseline ) {
		$scanner  = wpcybersec()->scanner;
		$change   = $changed ? 'modified' : 'new';
		$base     = $changed ? self::approved_base( $rel, $row, $executable ) : self::no_base();
		$severity = $scanner->max_severity( $hits );
		$hits     = array_merge( array( self::integrity_hit( $integrity, $rel ) ), $hits );
		if ( ! $baseline && $is_new ) {
			++$this->state['new'];
		} elseif ( ! $baseline && $changed ) {
			++$this->state['modified'];
		}

		if ( 'core_unknown_file' === $integrity || $severity >= Store::SEV_HIGH ) {
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, $base, $verify, max( Store::SEV_HIGH, $severity ) );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}

		if ( ! $baseline && ( $is_new || $changed ) && ! $this->is_own_code( $verify ) ) {
			$quarantine = $is_new
				? 'quarantine_exec' === (string) wpcybersec()->settings->get( 'file_mode', 'report' )
				: 'quarantine' === (string) wpcybersec()->settings->get( 'modified_action', 'report' );
			if ( $quarantine ) {
				return $this->quarantine_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
			}
		}
		$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * Hit that explains an integrity report (shown like a signature match).
	 *
	 * @param string $integrity Issue code.
	 * @param string $rel       Relative path.
	 * @return array
	 */
	private static function integrity_hit( $integrity, $rel ) {
		switch ( $integrity ) {
			case 'core_unknown_file':
				$title    = __( 'File in wp-admin or wp-includes that is not part of WordPress', 'qartvelo-guard' );
				$severity = Store::SEV_HIGH;
				break;
			case 'core_unknown_config':
				$title    = __( 'Server configuration file added to a WordPress core folder', 'qartvelo-guard' );
				$severity = Store::SEV_MEDIUM;
				break;
			default:
				$title    = __( 'PHP file in the WordPress root folder that is not part of WordPress', 'qartvelo-guard' );
				$severity = Store::SEV_MEDIUM;
		}
		return array(
			'sig'      => 'root_php' === $integrity ? 'root_unknown_php' : $integrity,
			'title'    => $title,
			'severity' => $severity,
			'line'     => 0,
			'snippet'  => Signatures::clean_snippet( $rel ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Item creation                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Creates a pending file item (deduplicated by path + hash).
	 *
	 * @param string $abs             Path.
	 * @param string $rel             Relative path.
	 * @param string $sha             Hash.
	 * @param array  $stat            Stat.
	 * @param string $change          new | modified.
	 * @param array  $base            approved_base().
	 * @param array  $hits            Signature hits.
	 * @param string $quarantine_path Held copy ('' when the file stays).
	 * @param string $status          Item status.
	 */
	private function record_file( $abs, $rel, $sha, array $stat, $change, array $base, array $hits, $quarantine_path = '', $status = Store::STATUS_PENDING ) {
		$store = wpcybersec()->store;
		if ( '' === $quarantine_path ) {
			$this->snapshot_current( $abs, $sha );
		}
		if ( $store->item_find_open( Store::TYPE_FILE, $rel, $sha ) ) {
			return;
		}
		$severity = $hits ? wpcybersec()->scanner->max_severity( $hits ) : Store::SEV_MEDIUM;
		$details  = self::base_details(
			array(
				'change' => $change,
				'hits'   => array_values( $hits ),
			),
			$base,
			$sha
		);
		$id = $store->item_insert(
			array(
				'type'            => Store::TYPE_FILE,
				'status'          => $status,
				'severity'        => $severity,
				'path'            => $rel,
				'original_path'   => $abs,
				'quarantine_path' => $quarantine_path,
				'sha256'          => $sha,
				'size'            => $stat['size'],
				'mime'            => $this->mime( $abs ),
				'source'          => 'scan',
				'details'         => $details,
			)
		);
		if ( $id ) {
			wpcybersec()->logger->log(
				'new' === $change ? 'file_new' : 'file_modified',
				'new' === $change
					/* translators: %s: relative path */
					? sprintf( __( 'Found a new file awaiting review: %s', 'qartvelo-guard' ), $rel )
					/* translators: %s: relative path */
					: sprintf( __( 'A monitored file changed: %s', 'qartvelo-guard' ), $rel ),
				array( 'item_id' => $id, 'path' => $rel, 'sha256' => $sha )
			);
			$this->notify_item( $id );
		}
	}

	/**
	 * Creates a threat item and optionally auto-quarantines critical hits. The
	 * item stays pending (with the held copy when quarantined) until the admin
	 * decides.
	 *
	 * @param string     $abs      Path.
	 * @param string     $rel      Relative path.
	 * @param string     $sha      Hash.
	 * @param array      $stat     Stat.
	 * @param array      $hits     Hits.
	 * @param string     $change   new | modified.
	 * @param array      $base     approved_base().
	 * @param array|null $verify   Checksum result.
	 * @param int        $severity Force a severity (default: from hits).
	 */
	private function record_threat( $abs, $rel, $sha, array $stat, array $hits, $change, array $base, $verify = null, $severity = 0 ) {
		$store = wpcybersec()->store;
		++$this->state['threats'];
		$this->snapshot_current( $abs, $sha );

		$existing = $store->item_find_open( Store::TYPE_THREAT, $rel, $sha );
		if ( $existing ) {
			return;
		}
		// Reported for the first time (alerts are only sent for these).
		$this->state['new_threats'] = ( isset( $this->state['new_threats'] ) ? (int) $this->state['new_threats'] : 0 ) + 1;

		$severity = $severity > 0 ? $severity : max( Store::SEV_HIGH, wpcybersec()->scanner->max_severity( $hits ) );
		$details  = self::base_details(
			array(
				'change' => $change,
				'hits'   => array_values( $hits ),
			),
			$base,
			$sha
		);
		if ( is_array( $verify ) && '' !== $verify['source'] ) {
			$details['verified'] = $verify['source'];
			if ( '' !== $verify['reason'] ) {
				$details['checksum'] = $verify['reason'];
			}
		}

		$quarantine_path = '';
		if ( Store::SEV_CRITICAL === $severity && wpcybersec()->settings->get( 'auto_quarantine', false ) && ! $this->is_own_code( $verify ) && ! Decisions::is_critical_path( $abs ) && 'dropin' !== self::generated_kind( $abs ) ) {
			$held = wpcybersec()->quarantine->hold( $abs, true );
			if ( ! is_wp_error( $held ) ) {
				$quarantine_path = $held['quarantine_path'];
				++$this->state['quarantined'];
				wpcybersec()->store->manifest_set_state( $rel, Store::STATE_THREAT );
			}
		}

		$id = $store->item_insert(
			array(
				'type'            => Store::TYPE_THREAT,
				'status'          => Store::STATUS_PENDING,
				'severity'        => $severity,
				'path'            => $rel,
				'original_path'   => $abs,
				'quarantine_path' => $quarantine_path,
				'sha256'          => $sha,
				'size'            => $stat['size'],
				'mime'            => $this->mime( $abs ),
				'source'          => 'scan',
				'details'         => $details,
			)
		);
		if ( $id ) {
			wpcybersec()->logger->log(
				'threat_found',
				sprintf(
					/* translators: 1: severity label, 2: relative path */
					__( '%1$s threat found: %2$s', 'qartvelo-guard' ),
					Store::severity_label( $severity ),
					$rel
				),
				array( 'item_id' => $id, 'path' => $rel, 'sha256' => $sha, 'severity' => $severity )
			);
			if ( '' !== $quarantine_path ) {
				wpcybersec()->logger->log(
					'file_quarantined',
					/* translators: %s: relative path */
					sprintf( __( 'Auto-quarantined critical threat %s.', 'qartvelo-guard' ), $rel ),
					array( 'item_id' => $id, 'path' => $rel )
				);
			}
			$this->notify_item( $id );
		}
	}

	/**
	 * The version a reported change of a file is compared with ("Last
	 * approved version" on the changes screen). The manifest row holds the
	 * version seen last, which may itself be waiting for a decision (pending)
	 * or be a threat: only a trusted or approved (allowlisted) version counts.
	 * Otherwise the last approved version an open report of the same file
	 * already carries is used, and when there is none, nothing.
	 *
	 * @param string     $rel        Relative path.
	 * @param array|null $row        Manifest row before this run.
	 * @param bool       $executable Executable name (allowlist entries are per kind of name).
	 * @return array { sha256: string ('' for none), state: string (state of the row when it was not approved) }
	 */
	public static function approved_base( $rel, $row, $executable ) {
		$none = self::no_base();
		if ( ! is_array( $row ) || ! isset( $row['sha256'] ) || '' === (string) $row['sha256'] ) {
			return $none;
		}
		$sha   = strtolower( (string) $row['sha256'] );
		$state = isset( $row['state'] ) ? (string) $row['state'] : Store::STATE_TRUSTED;
		$allow = wpcybersec()->allowlist;
		if ( Store::STATE_TRUSTED === $state || ( $allow && $allow->is_allowed_hash( $sha, (bool) $executable ) ) ) {
			return array(
				'sha256' => $sha,
				'state'  => '',
			);
		}
		$latest = null;
		foreach ( array( Store::TYPE_FILE, Store::TYPE_THREAT ) as $type ) {
			$open = wpcybersec()->store->item_find_open( $type, (string) $rel );
			if ( $open && ( null === $latest || (int) $open['id'] > (int) $latest['id'] ) ) {
				$latest = $open;
			}
		}
		$previous = $latest && ! empty( $latest['details']['previous_sha256'] ) ? strtolower( (string) $latest['details']['previous_sha256'] ) : '';
		if ( Snapshots::is_sha( $previous ) ) {
			return array(
				'sha256' => $previous,
				'state'  => '',
			);
		}
		return array(
			'sha256' => '',
			'state'  => $state,
		);
	}

	/**
	 * @return array approved_base() result for "no earlier version".
	 */
	private static function no_base() {
		return array(
			'sha256' => '',
			'state'  => '',
		);
	}

	/**
	 * Adds the comparison base to an item's details: previous_sha256 (the last
	 * approved version), or previous_state when the earlier version was never
	 * approved.
	 *
	 * @param array  $details Details.
	 * @param array  $base    approved_base().
	 * @param string $sha     Hash of the reported version.
	 * @return array
	 */
	public static function base_details( array $details, array $base, $sha ) {
		$previous = isset( $base['sha256'] ) ? (string) $base['sha256'] : '';
		if ( '' !== $previous && ! hash_equals( $previous, strtolower( (string) $sha ) ) ) {
			$details['previous_sha256'] = $previous;
		} elseif ( '' === $previous && ! empty( $base['state'] ) ) {
			$details['previous_state'] = (string) $base['state'];
		}
		return $details;
	}

	/**
	 * @param int $id Item id.
	 */
	private function notify_item( $id ) {
		$notifier = wpcybersec()->notifier;
		if ( $notifier && method_exists( $notifier, 'item_created' ) ) {
			$notifier->item_created( $id );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Phase: finishing                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Database scan step (when the run includes it), then for whole-site runs
	 * the missing core file count and the administrator check.
	 *
	 * @param float $deadline Microtime deadline of this tick.
	 * @return bool True when this part is complete; false to continue next tick.
	 */
	private function finish_extras( $deadline ) {
		if ( ! empty( $this->state['database'] ) && empty( $this->state['db_done'] ) ) {
			$db = wpcybersec()->db_scanner;
			if ( $db ) {
				$cursor = isset( $this->state['db'] ) && is_array( $this->state['db'] ) ? $this->state['db'] : $db->begin( (string) $this->state['id'] );
				$done   = true;
				try {
					$done = $db->step(
						$cursor,
						$deadline,
						function () {
							return $this->cancel_requested();
						}
					);
					if ( $done ) {
						$db->finish( $cursor );
					}
				} catch ( \Throwable $e ) {
					wpcybersec()->logger->log(
						'db_scan_failed',
						/* translators: %s: error message */
						sprintf( __( 'The database scan stopped: %s', 'qartvelo-guard' ), Signatures::clean_snippet( $e->getMessage() ) ),
						array( 'id' => $this->state['id'] )
					);
					$done = true;
				}
				$this->state['db_findings'] = isset( $cursor['findings'] ) ? (int) $cursor['findings'] : 0;
				if ( ! $done ) {
					$this->state['db']      = $cursor;
					$this->state['current'] = 'options' === $cursor['stage'] ? __( 'Database: options', 'qartvelo-guard' ) : __( 'Database: posts', 'qartvelo-guard' );
					return false;
				}
			}
			$this->state['db']      = null;
			$this->state['db_done'] = true;
		}

		if ( empty( $this->state['paths'] ) && empty( $this->state['extras_done'] ) ) {
			$this->state['extras_done']  = true;
			$this->state['missing_core'] = (int) wpcybersec()->scanner->missing_core_count();
			if ( $this->state['missing_core'] > 0 ) {
				wpcybersec()->logger->log(
					'core_files_missing',
					sprintf(
						/* translators: %s: number of files */
						_n( '%s WordPress core file is missing. Reinstall WordPress from Dashboard > Updates to restore it.', '%s WordPress core files are missing. Reinstall WordPress from Dashboard > Updates to restore them.', $this->state['missing_core'], 'qartvelo-guard' ),
						number_format_i18n( $this->state['missing_core'] )
					),
					array( 'id' => $this->state['id'], 'missing_core' => $this->state['missing_core'] )
				);
			}
			$watch = wpcybersec()->user_watch;
			if ( $watch ) {
				try {
					$this->state['new_admins'] = (int) $watch->check_all();
				} catch ( \Throwable $e ) {
					wpcybersec()->logger->log( 'admin_check_failed', Signatures::clean_snippet( $e->getMessage() ), array( 'id' => $this->state['id'] ) );
				}
			}
		}
		return true;
	}

	/**
	 * Deleted-file detection, cleanup and notifications.
	 *
	 * @param float $deadline Microtime deadline of this tick (the database scan
	 *                        may need several ticks).
	 */
	private function finish( $deadline = 0.0 ) {
		if ( ! $this->finish_extras( $deadline > 0 ? $deadline : microtime( true ) + self::DEFAULT_BUDGET ) ) {
			return; // The database scan continues next tick.
		}
		if ( $this->cancel_requested( true ) ) {
			$this->cancel_now();
			return;
		}
		$prefixes = ! empty( $this->state['prefixes'] ) ? (array) $this->state['prefixes'] : array( '' );
		// Rows written after this run started (trusted after a decision, an
		// update, an approved upload...) describe files that exist: keep them.
		$before = gmdate( 'Y-m-d H:i:s', (int) $this->state['started_at'] );

		foreach ( $prefixes as $prefix ) {
			do {
				$rows = wpcybersec()->store->manifest_unseen( $this->state['id'], 500, (string) $prefix, $before );
				if ( ! $rows ) {
					break;
				}
				$delete = array();
				$keep   = array();
				foreach ( $rows as $row ) {
					if ( $this->in_resumed_dir( (string) $row['path'] ) || $this->is_unreadable( (string) $row['path'] ) ) {
						// Listed over several ticks (a file added or renamed meanwhile
						// can have been missed) or not readable this time: the row is
						// kept, not deleted, so the file is not "new" on the next scan.
						$keep[] = $row['path_hash'];
						continue;
					}
					$delete[] = $row['path_hash'];
					++$this->state['deleted'];
					if ( Store::STATE_TRUSTED !== (string) $row['state'] ) {
						wpcybersec()->store->items_resolve_open( (string) $row['path'], 'file_gone' );
					}
				}
				wpcybersec()->store->manifest_delete( $delete );
				if ( $keep ) {
					wpcybersec()->store->manifest_touch( $keep, $this->state['id'] );
				}
			} while ( count( $rows ) >= 500 );
		}

		$this->cleanup_files( $this->state );

		$this->state['state']       = 'done';
		$this->state['current']     = '';
		$this->state['finished_at'] = time();
		$this->state['message']     = $this->summary( $this->state );

		if ( 'baseline' === $this->state['mode'] && empty( $this->state['paths'] ) ) {
			Network::update_option( self::BASELINE_OPTION, time(), false );
			Network::update_option( self::ROOT_OPTION, $this->root(), false );
		}
		if ( empty( $this->state['paths'] ) ) {
			// The folders outside the scan root are covered from now on: later
			// runs judge new files there like anywhere else.
			Network::update_option( self::EXTRA_OPTION, array_values( wp_list_pluck( (array) $this->state['extra'], 'p' ) ), false );
		}
		if ( wpcybersec()->snapshots && method_exists( wpcybersec()->snapshots, 'enforce_cap' ) ) {
			// Keep stored copies under their count and size limits (inode quotas).
			wpcybersec()->snapshots->enforce_cap( 5.0 );
		}
		$this->log_scope_notes();
		if ( ! empty( $this->state['backfill'] ) && empty( $this->state['paths'] ) && wpcybersec()->snapshots ) {
			// Every trusted file of the site has been looked at once: copies exist
			// now, unless the backfill was reset while this scan ran.
			wpcybersec()->snapshots->backfill_done( isset( $this->state['backfill_gen'] ) ? (int) $this->state['backfill_gen'] : null );
		}
		$this->settle_rebaseline_queue();

		$this->save_last();

		wpcybersec()->logger->log(
			'scan_finished',
			$this->state['message'],
			array(
				'id'           => $this->state['id'],
				'files'        => $this->state['files_done'],
				'new'          => $this->state['new'],
				'modified'     => $this->state['modified'],
				'deleted'      => $this->state['deleted'],
				'threats'      => $this->state['threats'],
				'new_threats'  => isset( $this->state['new_threats'] ) ? (int) $this->state['new_threats'] : 0,
				'quarantined'  => $this->state['quarantined'],
				'skipped'      => $this->state['skipped'],
				'unreadable'   => isset( $this->state['unreadable'] ) ? count( (array) $this->state['unreadable'] ) : 0,
				'database'     => ! empty( $this->state['database'] ),
				'db_findings'  => isset( $this->state['db_findings'] ) ? (int) $this->state['db_findings'] : 0,
				'missing_core' => isset( $this->state['missing_core'] ) ? (int) $this->state['missing_core'] : -1,
				'new_admins'   => isset( $this->state['new_admins'] ) ? (int) $this->state['new_admins'] : 0,
				'symlinks'     => (int) $this->state['symlinks'],
				'unscannable'  => (int) $this->state['unscannable'],
				'mem_limited'  => (int) $this->state['mem_limited'],
				'extra_roots'  => count( (array) $this->state['extra'] ),
			)
		);
		if ( ! empty( $this->state['unreadable'] ) ) {
			$list = array_values( (array) $this->state['unreadable'] );
			wpcybersec()->logger->log(
				'scan_unreadable',
				sprintf(
					/* translators: 1: number of folders and files, 2: examples */
					_n( '%1$d folder or file could not be read by the web server user and was skipped; its earlier fingerprints were kept. Give the web server user read access so it is scanned again: %2$s', '%1$d folders or files could not be read by the web server user and were skipped; their earlier fingerprints were kept. Give the web server user read access so they are scanned again: %2$s', count( $list ), 'qartvelo-guard' ),
					count( $list ),
					implode( ', ', array_slice( $list, 0, 5 ) ) . ( count( $list ) > 5 ? ', ...' : '' )
				),
				array( 'id' => $this->state['id'], 'paths' => array_slice( $list, 0, 20 ) )
			);
		}

		$notifier = wpcybersec()->notifier;
		if ( $notifier && method_exists( $notifier, 'scan_finished' ) ) {
			$notifier->scan_finished( $this->status() );
		}

		/**
		 * Fires when a scan finishes.
		 *
		 * @param array $status Final status.
		 */
		do_action( 'wpcybersec_scan_finished', $this->status() );
	}

	/**
	 * Remembers a folder or file the scan could not read (permissions), so
	 * finish() keeps its manifest rows instead of treating them as deleted and
	 * reporting every file in it as new on the next scan.
	 *
	 * @param string $path   Manifest path (a folder without its trailing slash).
	 * @param bool   $is_dir Folder (its whole subtree) or one file.
	 */
	private function note_unreadable( $path, $is_dir ) {
		++$this->state['skipped'];
		if ( ! isset( $this->state['unreadable'] ) || ! is_array( $this->state['unreadable'] ) ) {
			$this->state['unreadable'] = array();
		}
		$path  = Store::db_text( (string) $path );
		$entry = $is_dir ? rtrim( $path, '/' ) . '/' : $path;
		if ( count( $this->state['unreadable'] ) >= 100 || in_array( $entry, $this->state['unreadable'], true ) ) {
			return;
		}
		$this->state['unreadable'][] = $entry;
	}

	/**
	 * Whether a manifest path is (inside) something note_unreadable() recorded.
	 *
	 * @param string $path Manifest path.
	 * @return bool
	 */
	private function is_unreadable( $path ) {
		if ( empty( $this->state['unreadable'] ) ) {
			return false;
		}
		foreach ( (array) $this->state['unreadable'] as $entry ) {
			$entry = (string) $entry;
			if ( '/' === substr( $entry, -1 ) ) {
				if ( '/' === $entry || 0 === strpos( $path, $entry ) ) {
					return true;
				}
			} elseif ( $path === $entry ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a manifest path is inside a folder listed over several ticks.
	 *
	 * @param string $path Manifest path.
	 * @return bool
	 */
	private function in_resumed_dir( $path ) {
		if ( empty( $this->state['resumed'] ) ) {
			return false;
		}
		foreach ( (array) $this->state['resumed'] as $entry ) {
			$folder = Store::db_text( $this->encoded() ? rawurldecode( (string) $entry ) : (string) $entry );
			if ( '' === $folder || 0 === strpos( $path, $folder . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Logs what the summary only counts: symlinked folders that were not
	 * scanned and files that could not be scanned or read in full (examples).
	 */
	private function log_scope_notes() {
		if ( ! empty( $this->state['symlinks'] ) ) {
			wpcybersec()->logger->log(
				'scan_symlinks_skipped',
				sprintf(
					/* translators: 1: number of folders, 2: examples */
					_n( '%1$s symlinked folder was not scanned because it points outside the WordPress folders (%2$s). Add its target as the scan folder or scan it separately.', '%1$s symlinked folders were not scanned because they point outside the WordPress folders (for example %2$s). Add their targets as the scan folder or scan them separately.', (int) $this->state['symlinks'], 'qartvelo-guard' ),
					number_format_i18n( (int) $this->state['symlinks'] ),
					implode( ', ', (array) $this->state['symlink_list'] )
				),
				array( 'id' => $this->state['id'] )
			);
		}
		if ( ! empty( $this->state['mem_limited'] ) ) {
			wpcybersec()->logger->log(
				'scan_memory_limited',
				sprintf(
					/* translators: %s: number of files */
					_n( '%s file was not checked for malware because the PHP memory limit left too little room to read it. Raise memory_limit (or WP_MAX_MEMORY_LIMIT) or lower the largest file size to scan.', '%s files were not checked for malware because the PHP memory limit left too little room to read them. Raise memory_limit (or WP_MAX_MEMORY_LIMIT) or lower the largest file size to scan.', (int) $this->state['mem_limited'], 'qartvelo-guard' ),
					number_format_i18n( (int) $this->state['mem_limited'] )
				),
				array( 'id' => $this->state['id'] )
			);
		}
	}

	/* ------------------------------------------------------------------ */
	/* Lock and cancel request                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Takes the job lock. INSERT IGNORE succeeds for exactly one caller; an
	 * expired lock is taken over with a compare-and-swap on its old value, so
	 * two callers can never both win.
	 *
	 * @param float $hold Seconds before the lock counts as abandoned.
	 * @param float $wait Seconds to keep trying.
	 * @return string Lock value ('' when not acquired).
	 */
	private function acquire_lock( $hold, $wait = 0.0 ) {
		global $wpdb;
		$table = esc_sql( Network::lock_table() );
		$token = substr( md5( uniqid( 'wpcs-lock', true ) . wp_rand() . getmypid() ), 0, 16 );
		$until = microtime( true ) + max( 0.0, (float) $wait );
		$tries = 0;
		while ( true ) {
			$value = ( time() + (int) ceil( $hold ) ) . ':' . $token;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$added = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$table} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::LOCK_OPTION, $value ) );
			if ( $added ) {
				return $value;
			}
			$current = self::db_option( self::LOCK_OPTION );
			if ( null !== $current && (int) $current < time() ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$taken = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, self::LOCK_OPTION, $current ) );
				if ( $taken ) {
					return $value;
				}
			}
			++$tries;
			if ( null === $current && $tries < 3 ) {
				continue; // Released between the two queries: try again at once.
			}
			if ( microtime( true ) >= $until ) {
				return '';
			}
			usleep( 250000 );
		}
	}

	/**
	 * Extends the lock held by this tick.
	 *
	 * @return bool False when the lock was lost (expired and taken over).
	 */
	private function refresh_lock() {
		global $wpdb;
		if ( '' === $this->lock ) {
			return true;
		}
		$token = (string) substr( $this->lock, (int) strpos( $this->lock, ':' ) + 1 );
		$value = ( time() + (int) ceil( $this->lock_hold ) ) . ':' . $token;
		if ( $value === $this->lock ) {
			return true;
		}
		$table = esc_sql( Network::lock_table() );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$ok = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, self::LOCK_OPTION, $this->lock ) );
		if ( $ok ) {
			$this->lock = $value;
			return true;
		}
		return self::db_option( self::LOCK_OPTION ) === $this->lock;
	}

	/**
	 * Releases a lock this request holds (never someone else's).
	 *
	 * @param string $value Lock value.
	 */
	private function release_lock( $value ) {
		global $wpdb;
		if ( '' === (string) $value ) {
			return;
		}
		$table = esc_sql( Network::lock_table() );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s AND option_value = %s", self::LOCK_OPTION, (string) $value ) );
	}

	/**
	 * @param string $id Job id to cancel.
	 */
	private function request_cancel( $id ) {
		global $wpdb;
		$table = esc_sql( Network::lock_table() );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (option_name, option_value, autoload) VALUES (%s, %s, 'no') ON DUPLICATE KEY UPDATE option_value = VALUES(option_value)", self::CANCEL_OPTION, (string) $id ) );
		wp_cache_delete( self::CANCEL_OPTION, 'options' );
	}

	/**
	 * Drops a pending cancel request.
	 */
	private function clear_cancel() {
		global $wpdb;
		$table = esc_sql( Network::lock_table() );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s", self::CANCEL_OPTION ) );
		wp_cache_delete( self::CANCEL_OPTION, 'options' );
	}

	/**
	 * Whether cancel() asked the running job to stop. Reads the database at
	 * most once a second unless $force.
	 *
	 * @param bool $force Read now.
	 * @return bool
	 */
	private function cancel_requested( $force = false ) {
		$now = microtime( true );
		if ( ! $force && $now - $this->cancel_checked < 1.0 ) {
			return false;
		}
		$this->cancel_checked = $now;
		$value                = self::db_option( self::CANCEL_OPTION );
		return null !== $value && ! empty( $this->state['id'] ) && $value === (string) $this->state['id'];
	}

	/**
	 * Raw option value straight from the database (no object cache), for the
	 * values several processes coordinate through.
	 *
	 * @param string $name Option name.
	 * @return string|null
	 */
	private static function db_option( $name ) {
		global $wpdb;
		$table = esc_sql( Network::lock_table() );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$value = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$table} WHERE option_name = %s LIMIT 1", $name ) );
		return null === $value ? null : (string) $value;
	}

	/* ------------------------------------------------------------------ */
	/* State helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * @param bool $fresh Read the database, not this request's object cache
	 *                    (another runner may have saved the job meanwhile).
	 * @return array|null
	 */
	private function load( $fresh = false ) {
		if ( $fresh ) {
			Network::flush_option_cache( self::OPTION );
		}
		$state = Network::get_option( self::OPTION, null );
		return is_array( $state ) && ! empty( $state['id'] ) ? $state : null;
	}

	/**
	 * Persists the working state.
	 */
	private function save() {
		if ( null === $this->state ) {
			return;
		}
		Network::update_option( self::OPTION, $this->state, false );
	}

	/**
	 * Copies the final status into the last-scan option.
	 */
	private function save_last() {
		Network::update_option( self::LAST_OPTION, $this->status(), false );
	}

	/**
	 * Marks the job failed and cleans up. Never deletes manifest rows.
	 *
	 * @param string $message Error.
	 */
	private function fail( $message ) {
		if ( null === $this->state ) {
			$this->state = $this->load();
		}
		if ( ! $this->state ) {
			return;
		}
		$this->cleanup_files( $this->state );
		$this->state['state']       = 'failed';
		$this->state['current']     = '';
		$this->state['finished_at'] = time();
		$this->state['message']     = Signatures::clean_snippet( (string) $message );
		$this->save_last();
		wpcybersec()->logger->log(
			'scan_failed',
			/* translators: %s: error message */
			sprintf( __( 'Scan failed: %s', 'qartvelo-guard' ), $this->state['message'] ),
			array( 'id' => $this->state['id'] )
		);
	}

	/**
	 * Removes the list file for a job.
	 *
	 * @param array|null $state State.
	 */
	private function cleanup_files( $state ) {
		if ( ! is_array( $state ) || empty( $state['list_file'] ) ) {
			return;
		}
		$file = (string) $state['list_file'];
		$tmp  = ! empty( $state['tmp_dir'] ) ? (string) $state['tmp_dir'] : '';
		// A temp folder is only ever one this plugin created for a run.
		if ( '' !== $tmp && ! preg_match( '~/wpcybersec-jobs-[a-z0-9]{16}$~', $tmp ) ) {
			$tmp = '';
		}
		foreach ( array( $file, preg_replace( '~\.list$~', '.cur', $file ) ) as $path ) {
			$inside = Storage::is_within( $path, wpcybersec()->storage->jobs_dir() ) || ( '' !== $tmp && Storage::is_within( $path, $tmp ) );
			if ( $inside && @is_file( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				Fs::delete( $path );
			}
		}
		if ( '' !== $tmp && @is_dir( $tmp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::rmdir( $tmp );
		}
	}

	/**
	 * @param array|null $state State.
	 * @return bool
	 */
	private function is_active( $state ) {
		return is_array( $state ) && in_array( isset( $state['state'] ) ? $state['state'] : '', array( 'enumerating', 'processing', 'finishing' ), true );
	}

	/**
	 * A job that has not ticked in over an hour is considered stuck.
	 *
	 * @param array $state State.
	 * @return bool
	 */
	private function is_stale( array $state ) {
		$ticked = isset( $state['ticked_at'] ) ? (int) $state['ticked_at'] : (int) $state['started_at'];
		return ( time() - $ticked ) > self::STALE_SECONDS;
	}

	/**
	 * Scan root the job was started for.
	 *
	 * @return string
	 */
	private function root() {
		return ! empty( $this->state['root'] ) ? (string) $this->state['root'] : Paths::scan_root();
	}

	/**
	 * @return bool Whether list lines and stack entries are encoded.
	 */
	private function encoded() {
		return ! empty( $this->state['enc'] );
	}

	/**
	 * @param string $rel Relative path.
	 * @return string One list line (without the newline).
	 */
	private function encode_line( $rel ) {
		if ( ! $this->encoded() ) {
			return $rel;
		}
		return strtr(
			$rel,
			array(
				'%'  => '%25',
				"\r" => '%0D',
				"\n" => '%0A',
			)
		);
	}

	/**
	 * @param string $rel Relative folder.
	 */
	private function stack_push( $rel ) {
		$this->state['stack'][] = $this->encoded() ? rawurlencode( $rel ) : $rel;
	}

	/**
	 * @return string Relative folder.
	 */
	private function stack_pop() {
		$entry = (string) array_pop( $this->state['stack'] );
		return $this->encoded() ? rawurldecode( $entry ) : $entry;
	}

	/**
	 * Reads up to $count non-empty list lines from the stored offset. Does not
	 * move the offset: process() advances it per processed line.
	 *
	 * @param int $count Lines.
	 * @return array[]|false List of [ relative path, byte offset after the line ], false when the list cannot be read.
	 */
	private function read_lines( $count ) {
		$file = (string) $this->state['list_file'];
		$fh   = @fopen( $file, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- read line by line from an offset.
		if ( ! $fh ) {
			return false;
		}
		$offset = (int) $this->state['list_offset'];
		if ( $offset > 0 ) {
			$info = fstat( $fh );
			if ( ! is_array( $info ) || $offset > (int) $info['size'] || 0 !== fseek( $fh, $offset ) ) {
				fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- the scan file list is read line by line from an offset.
				return false; // Truncated or replaced: not the list this job wrote.
			}
		}
		$lines = array();
		while ( count( $lines ) < $count && false !== ( $line = fgets( $fh ) ) ) {
			$end  = ftell( $fh );
			$line = rtrim( $line, "\r\n" );
			if ( '' !== $line ) {
				$lines[] = array( $this->encoded() ? rawurldecode( $line ) : $line, (int) $end );
			}
		}
		$this->read_end = (int) ftell( $fh );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- the scan file list is read line by line from an offset.
		return $lines;
	}

	/**
	 * @param string $abs Path.
	 * @return array|null { size, mtime }
	 */
	private function stat( $abs ) {
		if ( ! @is_file( $abs ) || ! @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		$size  = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$mtime = @filemtime( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || false === $mtime ) {
			return null;
		}
		return array(
			'size'  => (int) $size,
			'mtime' => (int) $mtime,
		);
	}

	/**
	 * @param string $abs  Path.
	 * @param int    $size Size in bytes.
	 * @return string
	 */
	private function hash( $abs, $size ) {
		return self::fingerprint( $abs, $size );
	}

	/**
	 * Content fingerprint used in the manifest: the sha256 of the file, or for
	 * files larger than max(256 MB, max_file_mb) (backup archives), the sha256
	 * of their size, first MB and last MB. Hashing several GB in full would
	 * outlast max_execution_time and leave the job stuck on one batch.
	 *
	 * @param string $abs  Path.
	 * @param int    $size Size in bytes (-1 to read it).
	 * @return string '' when the file cannot be read.
	 */
	public static function fingerprint( $abs, $size = -1 ) {
		$abs  = (string) $abs;
		$size = (int) $size;
		if ( $size < 0 ) {
			$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $size ) {
				return '';
			}
			$size = (int) $size;
		}
		$cap    = self::HASH_CAP;
		$plugin = function_exists( 'wpcybersec' ) ? wpcybersec() : null;
		if ( $plugin && ! empty( $plugin->scanner ) ) {
			$cap = max( $cap, (int) $plugin->scanner->max_bytes() );
		}
		if ( $size <= $cap ) {
			$sha = @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return is_string( $sha ) ? $sha : '';
		}
		$chunk = 1048576;
		$head  = @file_get_contents( $abs, false, null, 0, $chunk ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		$tail  = @file_get_contents( $abs, false, null, max( 0, $size - $chunk ), $chunk ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( false === $head || false === $tail ) {
			return '';
		}
		$ctx = hash_init( 'sha256' );
		hash_update( $ctx, 'large:' . $size . ':' );
		hash_update( $ctx, $head );
		hash_update( $ctx, $tail );
		return hash_final( $ctx );
	}

	/**
	 * @param string $abs Path.
	 * @return string
	 */
	private function mime( $abs ) {
		$type = wp_check_filetype( basename( $abs ) );
		return ! empty( $type['type'] ) ? (string) $type['type'] : '';
	}

	/**
	 * Normalizes requested scan folders to absolute paths inside the scan root
	 * plus the relative prefixes for deleted detection and the DFS stack.
	 * Folders inside a fully walked folder of the scan set outside the root
	 * (Bedrock's web/app/plugins/foo) are accepted with absolute prefixes.
	 *
	 * @param array $paths Absolute folders.
	 * @return array { abs: string[], rel: string[], stack: string[] }
	 */
	private function normalize_paths( array $paths ) {
		$root  = Paths::scan_root();
		$abs   = array();
		$rel   = array();
		$stack = array();
		foreach ( $paths as $path ) {
			$norm = wp_normalize_path( (string) $path );
			if ( '' === $norm ) {
				continue;
			}
			$real = realpath( $norm );
			if ( $real ) {
				$norm = wp_normalize_path( $real );
			}
			$norm   = trailingslashit( $norm );
			$inside = 0 === strpos( $norm, $root );
			if ( ( ! $inside && ! Paths::in_full_scope( $norm ) ) || ! @is_dir( $norm ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue; // Refuse folders outside the scan set, and missing ones.
			}
			if ( Store::db_text( $norm ) !== $norm ) {
				continue; // Not storable in the job state; a whole-site scan covers it.
			}
			$prefix  = $inside ? ltrim( substr( $norm, strlen( $root ) ), '/' ) : $norm;
			$abs[]   = rtrim( $norm, '/' );
			$rel[]   = $prefix;
			$stack[] = rtrim( $prefix, '/' );
		}
		if ( ! $stack ) {
			$stack = array( '' );
		}
		return array(
			'abs'   => array_values( array_unique( $abs ) ),
			'rel'   => array_values( array_unique( $rel ) ),
			'stack' => array_values( array_unique( $stack ) ),
		);
	}

	/**
	 * @param array $state State.
	 * @return float 0..100
	 */
	private function percent( array $state ) {
		switch ( isset( $state['state'] ) ? $state['state'] : 'idle' ) {
			case 'enumerating':
				return 0.0;
			case 'processing':
				$total = (int) $state['files_total'];
				return $total > 0 ? round( min( 99.0, $state['files_done'] / $total * 100 ), 1 ) : 0.0;
			case 'finishing':
				return 99.0;
			case 'done':
				return 100.0;
			default:
				return 0.0;
		}
	}

	/**
	 * @param array $state State.
	 * @return string
	 */
	private function summary( array $state ) {
		$text = sprintf(
			/* translators: 1: files checked, 2: new, 3: modified, 4: deleted, 5: threats */
			__( 'Checked %1$s files. New: %2$s, modified: %3$s, deleted: %4$s, threats: %5$s.', 'qartvelo-guard' ),
			number_format_i18n( $state['files_done'] ),
			number_format_i18n( $state['new'] ),
			number_format_i18n( $state['modified'] ),
			number_format_i18n( $state['deleted'] ),
			number_format_i18n( $state['threats'] )
		);
		if ( isset( $state['missing_core'] ) && (int) $state['missing_core'] >= 0 ) {
			/* translators: %s: number of files */
			$text .= ' ' . sprintf( __( 'Missing core files: %s.', 'qartvelo-guard' ), number_format_i18n( (int) $state['missing_core'] ) );
		}
		if ( ! empty( $state['database'] ) ) {
			/* translators: %s: number of findings */
			$text .= ' ' . sprintf( __( 'Database findings: %s.', 'qartvelo-guard' ), number_format_i18n( isset( $state['db_findings'] ) ? (int) $state['db_findings'] : 0 ) );
		}
		if ( ! empty( $state['new_admins'] ) ) {
			/* translators: %s: number of accounts */
			$text .= ' ' . sprintf( __( 'New administrators: %s.', 'qartvelo-guard' ), number_format_i18n( (int) $state['new_admins'] ) );
		}
		if ( ! empty( $state['extra'] ) ) {
			/* translators: %s: number of folders */
			$text .= ' ' . sprintf( _n( 'Also scanned %s WordPress folder outside the scan folder.', 'Also scanned %s WordPress folders outside the scan folder.', count( (array) $state['extra'] ), 'qartvelo-guard' ), number_format_i18n( count( (array) $state['extra'] ) ) );
		}
		if ( ! empty( $state['unscannable'] ) ) {
			/* translators: %s: number of files */
			$text .= ' ' . sprintf( __( 'Could not be scanned: %s.', 'qartvelo-guard' ), number_format_i18n( (int) $state['unscannable'] ) );
		}
		if ( ! empty( $state['symlinks'] ) ) {
			/* translators: %s: number of folders */
			$text .= ' ' . sprintf( _n( '%s symlinked folder not scanned.', '%s symlinked folders not scanned.', (int) $state['symlinks'], 'qartvelo-guard' ), number_format_i18n( (int) $state['symlinks'] ) );
		}
		if ( ! empty( $state['mem_limited'] ) ) {
			/* translators: %s: number of files */
			$text .= ' ' . sprintf( __( 'Not checked for malware (memory limit too low): %s.', 'qartvelo-guard' ), number_format_i18n( (int) $state['mem_limited'] ) );
		}
		return $text;
	}

	/**
	 * @return array
	 */
	private function idle_status() {
		return array(
			'id'           => '',
			'state'        => 'idle',
			'mode'         => '',
			'malware'      => false,
			'trigger'      => '',
			'files_total'  => 0,
			'files_done'   => 0,
			'new'          => 0,
			'modified'     => 0,
			'deleted'      => 0,
			'threats'      => 0,
			'new_threats'  => 0,
			'quarantined'  => 0,
			'skipped'      => 0,
			'started_at'   => 0,
			'finished_at'  => 0,
			'current'      => '',
			'message'      => '',
			'percent'      => 0.0,
			'database'     => false,
			'db_findings'  => 0,
			'missing_core' => -1,
			'new_admins'   => 0,
			'symlinks'     => 0,
			'unscannable'  => 0,
			'mem_limited'  => 0,
			'extra_roots'  => 0,
		);
	}
}
