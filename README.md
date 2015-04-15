# WP-API Key Authentication Plugin

Access your WordPress site's data through an easy-to-use HTTP REST API.

**Important Note:** This is a community project, not an official REST API team project. Please note that this may have security and usability issues.

## BU Fork Changes

The original WP-API/Key-Auth project has been forked here to make some necessary changes.

[Issue #4](https://github.com/WP-API/Key-Auth/issues/4) raised some interesting issues with replay attacks. All of those have been addressed.

NOTE: When generating a signature in languages other than PHP, ensure that the json encoding is returning the same output as it would in PHP. For example, some languages (like Python) do not escape the forward slashes in strings. This could cause problems generating a matching signature.

## About

Allows Key Authentication access to the WordPress JSON API.

## Installation

Drop this directory in and activate it. You need to be using pretty permalinks
to use the plugin, as it uses custom rewrite rules to power the API.

## Issue Tracking

All tickets for the project are being tracked on [GitHub][].

[GitHub]: https://github.com/WP-API/Key-Auth
