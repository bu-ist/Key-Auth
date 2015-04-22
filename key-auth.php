<?php
/**
 * Plugin Name: JSON API Key Authentication
 * Description: API/Secret Key Authentication handler for the JSON API
 * Author: Paul Hughes and WP API Team
 * Author URI: https://github.com/WP-API
 * Version: 0.1
 * Plugin URI: https://github.com/WP-API/Key-Auth
 */


if ( defined( 'WP_CLI' ) && WP_CLI ) {
	include_once( dirname( __FILE__ ) . '/lib/class-wp-json-key-auth-cli.php' );

	WP_CLI::add_command( 'key-auth', 'WP_JSON_Key_Auth_CLI' );
}

/**
 * Checks the HTTP request and authenticates a user using an API key and shared secret.
 *
 * @param mixed $user The current user passed in the filter.
 */

class JSON_Key_Auth {
	const CONSUMER_KEY_LENGTH = 12;
	const CONSUMER_SECRET_LENGTH = 48;

	/**
	 * The primary handler for user authentication.
	 *
	 * @param mixed $user The current user (or bool) passing through the filter.
	 * @return mixed A user on success, or false on failure.
	 * @author Paul Hughes
	 */
	public static function authHandler( $user ) {
		// Don't authenticate twice
		if ( ! empty( $user ) ) {
			return $user;
		}

		if ( !isset( $_SERVER['HTTP_X_API_KEY'] ) || !isset( $_SERVER['HTTP_X_API_TIMESTAMP'] ) || !isset( $_SERVER['HTTP_X_API_SIGNATURE'] ) ) {
			return $user;
		}

		$user_id = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );
		$user_secret = get_user_meta( $user_id, 'json_shared_secret' );

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key' => $_SERVER['HTTP_X_API_KEY'],
			'timestamp' => $_SERVER['HTTP_X_API_TIMESTAMP'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_uri' => $_SERVER['REQUEST_URI'],
		);

		$signature_gen = self::generateSignature( $signature_args, $user_secret );
		$signature = $_SERVER['HTTP_X_API_SIGNATURE'];

		if ( $signature_gen != $signature ) {
			return false;
		}

		return $user_id;
	}

	/**
	 * @param array $args The arguments used for generating the signature. They should be, in order:
	 *                    'api_key', 'timestamp', 'request_method', and 'request_uri'.
	 *                    Timestamp should be the timestamp passed in the reques.
	 * @param string $secret The shared secret we are using to generate the hash.
	 * @return string
	 */
	public static function generateSignature( $args, $secret ) {
		return md5( json_encode( $args ) . $secret );
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @param string $api_key The API key attached to a user.
	 * @return bool
	 */
	public static function findUserIdByKey( $api_key ) {
		$user_args = array(
			'meta_query' => array(
				array(
					'key' => 'json_api_key',
					'value' => $api_key,
				),
			),
			'number' => 1,
			'fields' => array( 'ID' ),
		);
		$user = get_users( $user_args );
		if ( is_array( $user ) && !empty( $user ) ) {
			return $user[0]->ID;
		}

		return false;
	}

	/**
	 * Sets the response headers
	 * 
	 * @param  string $value
	 * @param  string $key
	 * @return null
	 */
	public static function setHeader( $value, $key='X-KEY-AUTH' ) {
		header( sprintf( '%s: %s', strtoupper( $key ), $value ) );
	}

	/**
	 * Adds key/secret for the user
	 * @param string $user   user_login for which the key auth will be enabled
	 * @param array $params With key/secret key-value pairs or empty
	 * @return array|false $data if successful returns array with ID/key/secret, else false
	 */
	public static function addKeyAuthForUser( $user, $params ) {

		// generate key/secret
		$meta = array(
			'key'    => wp_generate_password( self::CONSUMER_KEY_LENGTH, false ),
			'secret' => wp_generate_password( self::CONSUMER_SECRET_LENGTH, false ),
		);

		// allow params to override key/secret
		if ( empty( $params ) ) {
			$params = array();
		}
		$meta = array_merge( $meta, $params );

		// ensure the requested user exists
		$user = get_user_by( 'login', $user );
		if ( ! $user ) {
			return false;
		}

		// @todo: handle overwriting previously set key/secret
		// $user_meta = get_user_meta( $user->ID, 'json_api_key', true );
		// if ( $user_meta ) {
		// 	return array( 'success': false, 'msg': 'User has API Key and Secret already.' );
		// }

		// save key/secret to usermeta
		update_user_meta( $user->ID, 'json_api_key', $meta['key'] );
		update_user_meta( $user->ID, 'json_shared_secret', $meta['secret'] );
		$data = array_merge( array( 'ID' => $user->ID ), $meta );

		return $data;
	}
}

add_filter( 'determine_current_user', array( 'JSON_Key_Auth', 'authHandler' ), 20 );
