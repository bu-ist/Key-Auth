<?php
/**
 * Plugin Name: JSON API Key Authentication
 * Description: API/Secret Key Authentication handler for the JSON API
 * Author: Paul Hughes and WP API Team
 * Author URI: https://github.com/WP-API
 * Version: 0.1
 * Plugin URI: https://github.com/WP-API/Key-Auth
 */

/**
 * Checks the HTTP request and authenticates a user using an API key and shared secret.
 *
 * @param mixed $user The current user passed in the filter.
 */

class JSON_Key_Auth {

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

		// Ensure the requested timestamp is within a reasonable time
		$timestamp = time();
		$request_timestamp = intval( $_SERVER['HTTP_X_API_TIMESTAMP'] );
		$reasonable_threshold = apply_filters( 'key_auth_reasonable_threshold', 5 * MINUTE_IN_SECONDS );
		if ( abs( $timestamp - $request_timestamp ) > $reasonable_threshold ) {
			return false;
		}

		$user_id = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );
		$user_secret = get_user_meta( $user_id, 'json_shared_secret', true);

		if ( ! is_numeric( $user_id ) and ! $user_secret ) {
			return false;
		}

		// Check for the proper HTTP Parameters
		// Note: Remember to sort the keys when generating the json encoding
		$signature_args = array(
			'api_key' => $_SERVER['HTTP_X_API_KEY'],
			'ip' => $_SERVER['REMOTE_ADDR'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_post' => $_POST,
			'request_uri' => $_SERVER['REQUEST_URI'],
			'timestamp' => $request_timestamp,
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
		$algo = apply_filters( 'key_auth_signature_algo', 'sha256' );
		return hash( $algo, json_encode( $args ) . $secret );
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
}

add_filter( 'determine_current_user', array( 'JSON_Key_Auth', 'authHandler' ), 20 );
