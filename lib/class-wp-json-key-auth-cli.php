<?php

/**
 * Manage Key-Auth plugin's authentication secrets
 */
class WP_JSON_Key_Auth_CLI extends WP_CLI_Command {

	/**
	 * Adds Key Auth for <user>
	 * 
	 * ## OPTIONS
	 *
	 * <user>
	 * : User login
	 *
	 * [--key=<key>]
	 * : API key preferably of CONSUMER_KEY_LENGTH size (12)
	 * 
	 * [--secret=<secret>]
	 * : API secret preferably of CONSUMER_SECRET_LENGTH size (48)
	 *
	 * ## EXAMPLES
	 * 
	 *     wp key-auth username [--key=strSIZEis12C] [--secret=strSIZEis48CstrSIZEis48CstrSIZEis48CstrSIZEis48C]
	 */
	public function add( $_, $args ) {

		$user = $_[0];
		$result = JSON_Key_Auth::addKeyAuthForUser( $user, $args );
		var_dump($_);
		var_dump($args);
		if ( $result === false ) {
			WP_CLI::error( sprintf( 'Failed to create Key Auth for user %s',     $user ) );
		}

		WP_CLI::success( 'Created Key Auth with the following details:' );
		foreach( $result as $k => $v ) {
			WP_CLI::line( sprintf( '%s: %s', $k, $v ) );
		}

	}
}