<?php
/**
 * Plugin Name: Telegram 2 Adımlı Giriş (10 Haneli Kod)
 * Description: Yönetici ve üye girişlerinde Telegram botuna 10 haneli tek kullanımlık güvenlik kodu gönderir.
 * Version: 1.0.0
 * Requires PHP: 7.0
 * License: GPL-2.0-or-later
 * Text Domain: telegram-2fa-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TG2FA_Login {
	const CODE_LENGTH  = 10;
	const CODE_TTL     = 300; // saniye
	const MAX_ATTEMPTS = 5;
	const OPT_TOKEN    = 'tg2fa_bot_token';
	const OPT_CHAT     = 'tg2fa_chat_id';
	const META_TOKEN   = 'tg2fa_bot_token';
	const META_CHAT    = 'tg2fa_chat_id';

	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
		add_action( 'login_form_tg2fa', array( __CLASS__, 'verify_screen' ) );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		add_action( 'show_user_profile', array( __CLASS__, 'profile_fields' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile_fields' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save_profile' ) );
	}

	/* ---------- Ayarlar ---------- */

	public static function menu() {
		add_options_page( 'Telegram 2FA', 'Telegram 2FA', 'manage_options', 'tg2fa', array( __CLASS__, 'settings_page' ) );
	}

	public static function register_settings() {
		register_setting( 'tg2fa', self::OPT_CHAT, array( 'sanitize_callback' => array( __CLASS__, 'sanitize_chat' ) ) );
		register_setting( 'tg2fa', self::OPT_TOKEN, array( 'sanitize_callback' => array( __CLASS__, 'sanitize_token_option' ) ) );
	}

	public static function sanitize_chat( $v ) {
		$v = trim( (string) $v );
		return preg_match( '/^-?\d{1,20}$/', $v ) ? $v : '';
	}

	public static function sanitize_token( $v ) {
		$v = trim( (string) $v );
		return preg_match( '/^\d{5,15}:[A-Za-z0-9_-]{20,100}$/', $v ) ? $v : '';
	}

	public static function sanitize_token_option( $v ) {
		$v = trim( (string) $v );
		if ( '' === $v ) {
			return get_option( self::OPT_TOKEN, '' ); // boş bırakılırsa mevcut değeri koru
		}
		return self::sanitize_token( $v );
	}

	public static function settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap">
			<h1>Telegram 2 Adımlı Giriş</h1>
			<p>Kullanıcının profilinde kendi Chat ID/Bot Token değeri yoksa aşağıdaki genel değerler kullanılır. Hiçbiri tanımlı değilse o kullanıcı için 2. adım uygulanmaz.</p>
			<form method="post" action="options.php">
				<?php settings_fields( 'tg2fa' ); ?>
				<table class="form-table">
					<tr><th><label for="tg2fa_bot_token">Bot Token</label></th>
						<td><input type="password" id="tg2fa_bot_token" name="<?php echo esc_attr( self::OPT_TOKEN ); ?>" class="regular-text" autocomplete="off" placeholder="<?php echo get_option( self::OPT_TOKEN ) ? '(kayıtlı - değiştirmek için yeni değer girin)' : ''; ?>"></td></tr>
					<tr><th><label for="tg2fa_chat_id">Chat ID</label></th>
						<td><input type="text" id="tg2fa_chat_id" name="<?php echo esc_attr( self::OPT_CHAT ); ?>" class="regular-text" value="<?php echo esc_attr( get_option( self::OPT_CHAT, '' ) ); ?>"></td></tr>
				</table>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}

	public static function profile_fields( $user ) {
		?>
		<h2>Telegram 2 Adımlı Giriş</h2>
		<?php wp_nonce_field( 'tg2fa_profile_' . $user->ID, 'tg2fa_profile_nonce' ); ?>
		<table class="form-table">
			<tr><th><label for="tg2fa_chat">Telegram Chat ID</label></th>
				<td><input type="text" name="tg2fa_chat" id="tg2fa_chat" class="regular-text" value="<?php echo esc_attr( get_user_meta( $user->ID, self::META_CHAT, true ) ); ?>"></td></tr>
			<tr><th><label for="tg2fa_token">Telegram Bot Token</label></th>
				<td><input type="password" name="tg2fa_token" id="tg2fa_token" class="regular-text" autocomplete="off" placeholder="<?php echo get_user_meta( $user->ID, self::META_TOKEN, true ) ? '(kayıtlı - değiştirmek için yeni değer girin)' : ''; ?>">
				<p class="description">Boş bırakılırsa genel bot token kullanılır.</p></td></tr>
		</table>
		<?php
	}

	public static function save_profile( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) || ! isset( $_POST['tg2fa_profile_nonce'] )
			|| ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['tg2fa_profile_nonce'] ) ), 'tg2fa_profile_' . $user_id ) ) {
			return;
		}
		$chat = isset( $_POST['tg2fa_chat'] ) ? self::sanitize_chat( wp_unslash( $_POST['tg2fa_chat'] ) ) : '';
		if ( '' === $chat ) {
			delete_user_meta( $user_id, self::META_CHAT );
		} else {
			update_user_meta( $user_id, self::META_CHAT, $chat );
		}
		$token = isset( $_POST['tg2fa_token'] ) ? trim( wp_unslash( $_POST['tg2fa_token'] ) ) : '';
		if ( '' !== $token ) {
			$token = self::sanitize_token( $token );
			if ( '' !== $token ) {
				update_user_meta( $user_id, self::META_TOKEN, $token );
			}
		}
	}

	private static function credentials( $user_id ) {
		$chat  = get_user_meta( $user_id, self::META_CHAT, true );
		$token = get_user_meta( $user_id, self::META_TOKEN, true );
		if ( ! $chat ) {
			$chat = get_option( self::OPT_CHAT, '' );
		}
		if ( ! $token ) {
			$token = get_option( self::OPT_TOKEN, '' );
		}
		return ( $chat && $token ) ? array( $token, $chat ) : null;
	}

	/* ---------- Giriş akışı ---------- */

	private static $bypass = false;

	private static function hash_code( $code, $nonce ) {
		return hash_hmac( 'sha256', $code . '|' . $nonce, wp_salt( 'auth' ) );
	}

	private static function send( $token, $chat, $text ) {
		$res = wp_remote_post(
			'https://api.telegram.org/bot' . $token . '/sendMessage',
			array( 'timeout' => 10, 'sslverify' => true, 'body' => array( 'chat_id' => $chat, 'text' => $text ) )
		);
		return ! is_wp_error( $res ) && 200 === (int) wp_remote_retrieve_response_code( $res );
	}

	public static function on_login( $user_login, $user ) {
		if ( self::$bypass || ! ( $user instanceof WP_User ) ) {
			return;
		}
		$cred = self::credentials( $user->ID );
		if ( ! $cred ) {
			return; // Telegram tanımlı değil: kilitlenmeyi önlemek için 2. adım yok.
		}
		// İlk adımda verilen oturumu hemen kapat.
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		$login_url = wp_login_url();
		$code      = '';
		for ( $i = 0; $i < self::CODE_LENGTH; $i++ ) {
			$code .= random_int( 0, 9 );
		}
		$id    = wp_generate_password( 32, false, false );
		$nonce = wp_generate_password( 32, false, false );
		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$ok    = self::send( $cred[0], $cred[1], sprintf( "%s giriş kodunuz: %s\nKullanıcı: %s\nGeçerlilik: %d dk. Bu kodu kimseyle paylaşmayın.", $site, $code, $user->user_login, self::CODE_TTL / 60 ) );

		if ( ! $ok ) {
			wp_safe_redirect( add_query_arg( 'tg2fa_error', 'send', $login_url ) );
			exit;
		}
		$remember = ! empty( $_POST['rememberme'] );
		$redirect = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), admin_url() ) : admin_url();
		set_transient( 'tg2fa_' . $id, array(
			'uid'      => $user->ID,
			'hash'     => self::hash_code( $code, $nonce ),
			'nonce'    => $nonce,
			'tries'    => 0,
			'remember' => $remember,
			'redirect' => $redirect,
		), self::CODE_TTL );

		// Kimlik, tarayıcıya bağlanır (çerez) ve formda ayrıca gönderilir.
		setcookie( 'tg2fa_id', $id, array( 'expires' => time() + self::CODE_TTL, 'path' => COOKIEPATH, 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Strict' ) );
		wp_safe_redirect( add_query_arg( array( 'action' => 'tg2fa', 'k' => $id ), $login_url ) );
		exit;
	}

	public static function verify_screen() {
		$id   = isset( $_REQUEST['k'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', wp_unslash( $_REQUEST['k'] ) ) : '';
		$ck   = isset( $_COOKIE['tg2fa_id'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', wp_unslash( $_COOKIE['tg2fa_id'] ) ) : '';
		$data = $id ? get_transient( 'tg2fa_' . $id ) : false;
		$err  = '';

		if ( ! $data || ! hash_equals( $id, $ck ) ) {
			wp_safe_redirect( add_query_arg( 'tg2fa_error', 'expired', wp_login_url() ) );
			exit;
		}

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$code = isset( $_POST['tg2fa_code'] ) ? preg_replace( '/\D/', '', wp_unslash( $_POST['tg2fa_code'] ) ) : '';
			$data['tries']++;
			if ( strlen( $code ) === self::CODE_LENGTH && hash_equals( $data['hash'], self::hash_code( $code, $data['nonce'] ) ) ) {
				delete_transient( 'tg2fa_' . $id );
				setcookie( 'tg2fa_id', '', time() - HOUR_IN_SECONDS, COOKIEPATH );
				$user = get_user_by( 'id', $data['uid'] );
				if ( $user ) {
					self::$bypass = true;
					wp_set_current_user( $user->ID );
					wp_set_auth_cookie( $user->ID, $data['remember'] );
					do_action( 'wp_login', $user->user_login, $user );
					wp_safe_redirect( $data['redirect'] );
					exit;
				}
			}
			if ( $data['tries'] >= self::MAX_ATTEMPTS ) {
				delete_transient( 'tg2fa_' . $id );
				wp_safe_redirect( add_query_arg( 'tg2fa_error', 'locked', wp_login_url() ) );
				exit;
			}
			set_transient( 'tg2fa_' . $id, $data, self::CODE_TTL );
			$err = 'Kod hatalı.';
		}

		login_header( 'Güvenlik Kodu', '<p class="message">Telegram\'a gönderilen 10 haneli kodu girin.</p>' . ( $err ? '<div id="login_error">' . esc_html( $err ) . '</div>' : '' ) );
		?>
		<form method="post" action="<?php echo esc_url( add_query_arg( array( 'action' => 'tg2fa', 'k' => $id ), wp_login_url() ) ); ?>">
			<p><label for="tg2fa_code">Güvenlik Kodu</label>
			<input type="text" name="tg2fa_code" id="tg2fa_code" class="input" maxlength="10" inputmode="numeric" pattern="[0-9]{10}" autocomplete="one-time-code" autofocus required></p>
			<p class="submit"><input type="submit" class="button button-primary button-large" value="Doğrula"></p>
		</form>
		<?php
		login_footer();
		exit;
	}
}

add_filter( 'wp_login_errors', function ( $errors ) {
	$map = array(
		'send'    => 'Güvenlik kodu Telegram\'a gönderilemedi. Giriş engellendi.',
		'expired' => 'Doğrulama süresi doldu. Lütfen tekrar giriş yapın.',
		'locked'  => 'Çok fazla hatalı deneme. Lütfen tekrar giriş yapın.',
	);
	$e = isset( $_GET['tg2fa_error'] ) ? sanitize_key( wp_unslash( $_GET['tg2fa_error'] ) ) : '';
	if ( isset( $map[ $e ] ) ) {
		$errors->add( 'tg2fa', $map[ $e ] );
	}
	return $errors;
} );

TG2FA_Login::init();
