<?php

//	File Location: /system/api/ldaphelper.inc.php

if ( !defined( 'WI_VERSION' ) ) die( -1 );

class System_Api_LDAPHelper
{

	private $_params;
	private $_ldap_connection = false;
	
	public function __construct( $params = array() )
	{
		$this->setParams( $params );
	}
	
	//	set params
	public function setParams( $params = array() )
	{
		//	default ldap parameters
		$default_params = array(
			'ldap_domain_suffix'	=> 'intra',
			'ldap_server'			=> 'isp-dc2.intra.ispras.ru',
			'ldap_user_ou'			=> 'cn=Users,dc=intra,dc=ispras,dc=ru',
			'ldap_group_ou'			=> 'dc=intra,dc=ispras,dc=ru',
            'ldap_user_filter'      => '(&(objectClass=user)(!(objectClass=computer))(mail=%s@ispras.ru))'
		);
		
		//	merge provided params into defaults
		foreach ( $params as $key => $value )
			if ( isset( $default_params[$key] ) )
				$default_params[$key] = $value;
		
		//	update the object
		$this->_params = $default_params;
	}
	
	//	connect to ldap
	public function connect()
	{
		if ( $this->_ldap_connection ) return true;
		$this->_ldap_connection = @ldap_connect( $this->_params['ldap_server'] );
        // throw new Exception("111111111111111111");
		if ( ! $this->_ldap_connection ) throw new Exception("Could not connect to LDAP server.");
        ldap_set_option($this->_ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
	}
	
	//	bind to ldap server
	public function bind( $user, $password )
	{
		if ( ! $this->_ldap_connection ) $this->connect();
		if ( @ldap_bind( $this->_ldap_connection, "{$user}@{$this->_params['ldap_domain_suffix']}", $password ) ) return true;
		else return false;
	}
	
	//	get user info from ldap
	public function getUserInfo( $user )
	{
		// search for the user
        $base  = $this->_params['ldap_user_ou'];
        $filter = sprintf( $this->_params['ldap_user_filter'], str_replace( array( "(", ")", "*" ), array( "\(", "\)", "\*"), $user ) );
        ldap_set_option($this->_ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
		if ( ! $results = @ldap_search(
			$this->_ldap_connection,
			$base,
			$filter,
			array( 'mail', 'dn', 'sn', 'givenName', 'displayName')
		) ) return false; // user is not found!
		
		// get the user details
		$user = @ldap_get_entries( $this->_ldap_connection, $results );
		
		// if there are more than one users returned throw and exception
		if ($user['count'] > 1) throw new Exception("Too many users returned from LDAP search.");
		
		$return = array(
			'dn' => $user[0]['dn']
		);
		for ( $i = 0; $i < $user[0]['count']; $i++ )
		{
			$name = $user[0][$i];
			$return[$name] = $user[0][$name][0];
		}
		
		// otherwise return the user
		return $return;
	}
	
	//	check user memberships
	public function isMember( $groupname, $userdn, &$checkedgroups=array() )
	{
		// check to see if group has already been checked, if it has return false
		// otherwise add it to the array of checked groups, this will prevent
		// getting stuck in a check loop
		if ( in_array( $groupname, $checkedgroups ) ) return false;
		$checkedgroups[] = $groupname;
		
		// search for group to get dn and members
		if ( ! $results = @ldap_search(
			$this->_ldap_connection,
			$this->_params['ldap_group_ou'],
			sprintf( $this->_params['ldap_group_filter'], str_replace( array( "(", ")", "*" ), array( "\(", "\)", "\*" ), $groupname ) ),
			array( 'dn', 'cn', 'member' )
		)) return false; // no GROUP with that name found
		
		// get the requested attributes from the query
		$group = @ldap_get_entries( $this->_ldap_connection, $results );
		
		// check to make sure we haven't found two groups
		if ( $group['count'] > 1 ) throw new exception("Too many groups returned by LDAP.");
		
		// if this is true the user is a direct member of the group
		if ( @ldap_compare( $this->_ldap_connection, $group[0]['dn'], 'member', $userdn ) === true ) return true;
		
		// check to see if any other members were returned
		if ( ! isset( $group[0]['member'] ) ) return false;
		
		// otherwise we need to search any member groups
		for ( $i=0; $i < $group[0]['member']['count']; $i++ )
		{
			// don't bother checking groups that have already been checked
			$groupname = preg_replace( "/CN=([^,]+),.*/i", "$1", $group[0]['member'][$i] );
			if ( $this->isMember( $groupname, $userdn, $checkedgroups ) ) return true;
		}
		
		// if we never find it return false
		return false;
	}

}
?>
