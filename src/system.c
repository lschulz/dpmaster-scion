/*
	system.c

	System specific code for dpmaster

	Copyright (C) 2008-2011  Mathieu Olivier

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include "common.h"
#include "system.h"


// ---------- Constants ---------- //

#ifndef WIN32

// Default path we use for chroot
# define DEFAULT_JAIL_PATH "/var/empty/"

// User we use by default for dropping super-user privileges
# define DEFAULT_LOW_PRIV_USER "nobody"

#endif

#define MAX_UNIX_SOCK_ADDR_LEN 32
#define UNIX_SOCK_LOC_TEMPLATE "/tmp/dpmaster_%d_loc_%d.sock"
#define UNIX_SOCK_PAN_TEMPLATE "/tmp/dpmaster_%d_pan_%d.sock"

// ---------- Private variables ---------- //

#ifndef WIN32

// Path we use for chroot
static const char* jail_path = DEFAULT_JAIL_PATH;

// Low privileges user
static const char* low_priv_user = DEFAULT_LOW_PRIV_USER;

// File descriptor to /dev/null, used by the daemonization process
static int null_device = -1;

#endif


// ---------- Public variables ---------- //

// The master sockets
unsigned int nb_sockets = 0;
listen_socket_t listen_sockets [MAX_LISTEN_SOCKETS];

// The port we use by default
unsigned short master_port = DEFAULT_MASTER_PORT;

// System specific command line options
const cmdlineopt_t sys_cmdline_options [] =
{
#ifndef WIN32
	{
		"daemon",
		NULL,
		"Run as a daemon",
		{ 0, 0 },
		'D',
		0,
		0
	},
	{
		"jail-path",
		"<jail_path>",
		"Use <jail_path> as chroot path (default: " DEFAULT_JAIL_PATH ")\n"
		"   Only available when running with super-user privileges",
		{ 0, 0 },
		'j',
		1,
		1
	},
	{
		"user",
		"<user>",
		"Use <user> privileges (default: " DEFAULT_LOW_PRIV_USER ")\n"
		"   Only available when running with super-user privileges",
		{ 0, 0 },
		'u',
		1,
		1
	},
#endif
	{
		NULL,
		NULL,
		NULL,
		{ 0, 0 },
		'\0',
		0,
		0
	}
};

// Daemon state
daemon_state_t daemon_state = DAEMON_STATE_NO;


// ---------- Private functions ---------- //

/*
====================
Sys_CloseSocket

Close a network socket
====================
*/
static void Sys_CloseSocket (socket_t sock)
{
#ifdef WIN32
	closesocket (sock);
#else
	close (sock);
#endif
}


/*
====================
Sys_BuildSockaddr

Build a sockaddr
====================
*/
static qboolean Sys_BuildSockaddr (const char* addr_name, const char* port_name,
								   int addr_family_hint,
								   struct sockaddr_storage* sock_address,
								   socklen_t* sock_address_len)
{
	char port_buff [8];
	struct addrinfo hints;
	struct addrinfo* addrinf = NULL;
	int err;

	// If there is no port, use the default one
	if (port_name == NULL)
	{
		snprintf (port_buff, sizeof (port_buff), "%hu", master_port);
		port_buff[sizeof (port_buff) - 1] = '\0';
		port_name = port_buff;
	}

	memset(&hints, 0, sizeof (hints));
	hints.ai_family = addr_family_hint;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(addr_name, port_name, &hints, &addrinf);
	if (err != 0 || addrinf == NULL)
	{
		Com_Printf (MSG_ERROR, "> ERROR: can't resolve %s:%s (%s)\n",
					addr_name, port_name, gai_strerror (err));

		if (addrinf != NULL)
			freeaddrinfo (addrinf);
		return false;
	}

	assert(addrinf->ai_addrlen <= sizeof (*sock_address));
	*sock_address_len = (socklen_t)addrinf->ai_addrlen;
	memcpy (sock_address, addrinf->ai_addr, addrinf->ai_addrlen);

	freeaddrinfo (addrinf);
	return true;
}


/*
====================
Sys_BuildUnixSockaddr

Build a sockaddr for a unix domain socket
====================
*/
static qboolean Sys_BuildUnixSockaddr(const char* addr_name,
									  struct sockaddr_storage* sock_address,
									  socklen_t* sock_address_len)
{
	size_t len = strlen (addr_name) + 1;
	struct sockaddr_un* unix_sock = (struct sockaddr_un*)sock_address;

	if (sizeof(unix_sock->sun_path) < len)
		return false;

	unix_sock->sun_family = AF_UNIX;
	memcpy (unix_sock->sun_path, addr_name, len);
	*sock_address_len = sizeof(struct sockaddr_un);

	return true;
}


/*
====================
Sys_StringToSockaddr

Resolve an address
====================
*/
static qboolean Sys_StringToSockaddr (const char* address,
									  struct sockaddr_storage* sock_address,
									  socklen_t* sock_address_len)
{
	const char* addr_start;
	const char* addr_end = NULL;
	const char* port_name = NULL;
	int addr_family = AF_UNSPEC;
	size_t addr_length;
	char addr_buff [128];

	// If it's a bracketed IPv6 address
	if (address[0] == '[')
	{
		const char* end_bracket = strchr(address, ']');

		if (end_bracket == NULL)
		{
			Com_Printf (MSG_ERROR,
						"> ERROR: IPv6 address has no closing bracket (%s)\n",
						address);
			return false;
		}

		if (end_bracket[1] != ':' && end_bracket[1] != '\0')
		{
			Com_Printf (MSG_ERROR,
						"> ERROR: invalid end of bracketed IPv6 address (%s)\n",
						address);
			return false;
		}

		if (end_bracket[1] == ':')
			port_name = end_bracket + 2;

		addr_family = AF_INET6;
		addr_start = &address[1];
		addr_end = end_bracket;
	}
	else
	{
		const char* first_colon;

		addr_start = address;

		// If it's a numeric non-bracket IPv6 address (-> no port),
		// or it's a numeric IPv4 address, or a name, with a port
		first_colon = strchr(address, ':');
		if (first_colon != NULL)
		{
			const char* last_colon = strrchr(first_colon + 1, ':');

			// If it's an numeric IPv4 address, or a name, with a port
			if (last_colon == NULL)
			{
				addr_end = first_colon;
				port_name = first_colon + 1;
			}
			else
				addr_family = AF_INET6;
		}
	}

	if (addr_end != NULL)
	{
		assert(addr_end >= addr_start);
		addr_length = addr_end - addr_start;
	}
	else
		addr_length = strlen (addr_start);

	// Check the address length
	if (addr_length >= sizeof (addr_buff))
	{
		Com_Printf (MSG_ERROR,
					"> ERROR: address too long to be resolved (%s)\n",
					address);
		return false;
	}
	memcpy (addr_buff, addr_start, addr_length);
	addr_buff[addr_length] = '\0';

	return Sys_BuildSockaddr (addr_buff, port_name, addr_family, sock_address, sock_address_len);
}


/*
====================
Sys_SetAddrMasterPort

Add master_port to IPv4/6 address if it does not have a port already.
Returns false if the address could not be parsed at all. A return value of true
does not guaranteed the address is valid.
====================
*/
qboolean Sys_SetAddrMasterPort(const char* restrict addr_in,
							   char* restrict addr_out,
							   size_t addr_out_len)
{
	assert (addr_in != NULL);
	if (addr_in[0] == '[')
	{
		// bracketed IPv6 address
		const char* end_bracket = strchr(&addr_in[1], ']');
		if (end_bracket == NULL)
			return false; // not a valid address

		if (end_bracket[1] == '\0')
		{
			// assume bracketed IPv6 address without port
			snprintf(addr_out, addr_out_len, "%s:%d", addr_in, master_port);
			return true;
		}
		else if (end_bracket[1] == ':')
        {
            snprintf(addr_out, addr_out_len, "%s", addr_in);
			return true; // assume bracketed IPv6 address with port
        }
		else
			return false; // not a valid address
	}
	else
	{
		const char* first_colon = strchr(addr_in, ':');
		if (first_colon == NULL)
		{
			// assume IPv4 address without port
			snprintf(addr_out, addr_out_len, "%s:%d", addr_in, master_port);
            return true;
		}
		else
		{
			const char* last_colon = strrchr(&first_colon[1], ':');
			if (last_colon != NULL)
            {
                // assume IPv6 address without port
                snprintf(addr_out, addr_out_len, "[%s]:%d", addr_in, master_port);
                return true;
            }
            else
            {
                snprintf(addr_out, addr_out_len, "%s", addr_in);
				return true; // assume IPv4 address with port
            }
		}
	}
}


/*
====================
Sys_CreateIpListenSocket

Create regular IP listening socket
====================
*/
static qboolean Sys_CreateIpListenSocket (listen_socket_t* listen_sock,
										  unsigned int* sock_ind)
{
	socket_t crt_sock;
	int addr_family;

	addr_family = listen_sock->local_addr.ss_family;
	crt_sock = socket (addr_family, SOCK_DGRAM, IPPROTO_UDP);
	if (crt_sock == INVALID_SOCKET)
	{
		// If the address family isn't supported but the socket is optional, don't fail!
		if (Sys_GetLastNetError() == NETERR_AFNOSUPPORT &&
			listen_sock->optional)
		{
			Com_Printf (MSG_WARNING, "> WARNING: protocol %s isn't supported\n",
						(addr_family == AF_INET) ? "IPv4" :
						((addr_family == AF_INET6) ? "IPv6" : "UNKNOWN"));

			if (*sock_ind + 1 < nb_sockets)
				memmove (&listen_sockets[*sock_ind], &listen_sockets[*sock_ind + 1],
							(nb_sockets - *sock_ind - 2) * sizeof (listen_sockets[0]));

			(*sock_ind)--;
			nb_sockets--;
			return true;
		}

		Com_Printf (MSG_ERROR, "> ERROR: socket creation failed (%s)\n",
					Sys_GetLastNetErrorString ());
		return false;
	}

	if (addr_family == AF_INET6)
	{
// Win32's API only supports it since Windows Vista, but fortunately
// the default value is what we want on Win32 anyway (IPV6_V6ONLY = true)
#ifdef IPV6_V6ONLY
		int ipv6_only = 1;
		if (setsockopt (crt_sock, IPPROTO_IPV6, IPV6_V6ONLY,
						(const void *)&ipv6_only, sizeof(ipv6_only)) != 0)
		{
#ifdef WIN32
			// This flag isn't supported before Windows Vista
			if (Sys_GetLastNetError() != NETERR_NOPROTOOPT)
#endif
			{
				Com_Printf (MSG_ERROR, "> ERROR: setsockopt(IPV6_V6ONLY) failed (%s)\n",
							Sys_GetLastNetErrorString ());
				return false;
			}
		}
#endif
	}

	if (listen_sock->local_addr_name != NULL)
	{
		const char* addr_str;

		addr_str = Sys_SockaddrToString(&listen_sock->local_addr,
										listen_sock->local_addr_len);
		Com_Printf (MSG_NORMAL, "> Listening on address %s (%s)\n",
					listen_sock->local_addr_name,
					addr_str);
	}
	else
		Com_Printf (MSG_NORMAL, "> Listening on all %s addresses\n",
					addr_family == AF_INET6 ? "IPv6" : "IPv4");

	if (bind (crt_sock, (struct sockaddr*)&listen_sock->local_addr,
				listen_sock->local_addr_len) != 0)
	{
		Com_Printf (MSG_ERROR, "> ERROR: socket binding failed (%s)\n",
					Sys_GetLastNetErrorString ());
		return false;
	}

	listen_sock->socket = crt_sock;
	return true;
}


/*
====================
Sys_CreateScionListenSocket

Create SCION listening connection and a proxy socket
====================
*/
static qboolean Sys_CreateScionListenSocket (listen_socket_t* listen_sock,
											 unsigned int* sock_ind)
{
	PanError err = PAN_ERR_OK;
	char local_addr[128] = {0};
	char unix_addr[MAX_UNIX_SOCK_ADDR_LEN] = {0};

	if (listen_sock->scion_local_addr == NULL)
	{
		// Since binding to wildcard addresses is not supported in SCION at the
		// moment, this will bind to a default local IP (most likely localhost).
		snprintf(local_addr, sizeof(local_addr), "0.0.0.0:%d", master_port);
	}
	else
	{
		if (! Sys_SetAddrMasterPort (listen_sock->scion_local_addr, local_addr, sizeof(local_addr)))
		{
			Com_Printf (MSG_ERROR, "> ERROR: invalid address %s\n", listen_sock->scion_local_addr);
			return false;
		}
	}

	// Create listen connection
	err = PanListenUDP (local_addr, PAN_INVALID_HANDLE, &listen_sock->conn);
	if (err != PAN_ERR_OK)
	{
		if (err == PAN_ERR_ADDR_SYNTAX)
			Com_Printf (MSG_ERROR, "> ERROR: invalid address %s\n", local_addr);
		else if (err == PAN_ERR_FAILED)
			Com_Printf (MSG_ERROR, "> ERROR: PAN socket binding to %s failed\n", local_addr);
		return false;
	}
	else
	{
		char* addr = NULL;
		PanUDPAddr pan_addr = PanListenConnLocalAddr (listen_sock->conn);
		addr = PanUDPAddrToString (pan_addr);
		PanDeleteHandle(pan_addr);
		if (! addr) return false;
		Com_Printf (MSG_NORMAL, "> Listening on address %s\n",
					addr);
		free(addr);
	}

	// Create PAN end of unix socket pair
	snprintf(unix_addr, sizeof(unix_addr), UNIX_SOCK_PAN_TEMPLATE, getpid(), *sock_ind);
	err = PanNewListenSockAdapter (listen_sock->conn,
									unix_addr,
									((struct sockaddr_un*)&listen_sock->local_addr)->sun_path,
									&listen_sock->adapter);
	if (err != PAN_ERR_OK)
	{
		Com_Printf (MSG_ERROR, "> ERROR: unix socket binding to %s failed\n",
					unix_addr);
		return false;
	}

	// Create local end of unix socket pair
	listen_sock->socket = socket (AF_UNIX, SOCK_DGRAM, 0);
	if (listen_sock->socket == INVALID_SOCKET)
	{
		Com_Printf (MSG_ERROR, "> ERROR: unix socket creation failed (%s)\n",
					Sys_GetLastNetErrorString ());
		return false;
	}

	unlink(((struct sockaddr_un*)&listen_sock->local_addr)->sun_path);
	if (bind (listen_sock->socket, (struct sockaddr*)&listen_sock->local_addr,
			  listen_sock->local_addr_len) != 0)
	{
		Com_Printf (MSG_ERROR, "> ERROR: unix socket binding to %s failed (%s)\n",
					((struct sockaddr_un*)&listen_sock->local_addr)->sun_path,
					Sys_GetLastNetErrorString ());
		return false;
	}

	// Connect our socket to the Go socket so we can use plain send()
	struct sockaddr_un remote;
	remote.sun_family = AF_UNIX;
	strncpy (remote.sun_path, unix_addr, sizeof(remote.sun_path) - 1);
	remote.sun_path[sizeof(remote.sun_path) - 1] = '\0';
	if (connect (listen_sock->socket, (struct sockaddr*)&remote, sizeof(remote)))
	{
		Com_Printf (MSG_ERROR, "> ERROR: connection to %s failed (%s)\n",
					unix_addr,
					Sys_GetLastNetErrorString ());
		return false;
	}

	return true;
}

// ---------- Public functions (listening sockets) ---------- //

/*
====================
Sys_CloseAllSockets

Close all network sockets
====================
*/
void Sys_CloseAllSockets (void)
{
	size_t sock_ind;
	for (sock_ind = 0; sock_ind < nb_sockets; sock_ind++)
	{
		listen_socket_t* sock = &listen_sockets[sock_ind];

		if (sock->socket != -1)
		{
			Sys_CloseSocket (sock->socket);
			unlink(((struct sockaddr_un*)&sock->local_addr)->sun_path);
		}
		if (sock->adapter != PAN_INVALID_HANDLE)
		{
			PanListenSockAdapterClose(sock->adapter);
			PanDeleteHandle(sock->adapter);
			sock->adapter = PAN_INVALID_HANDLE;
		}
		if (sock->conn != PAN_INVALID_HANDLE)
		{
			PanListenConnClose(sock->conn);
			PanDeleteHandle(sock->conn);
			sock->conn = PAN_INVALID_HANDLE;
		}
	}
	nb_sockets = 0;
}


/*
====================
Sys_DeclareListenAddress

Step 1 - Add a listen socket to the listening socket list
====================
*/
qboolean Sys_DeclareListenAddress (const char* local_addr_name)
{
	if (nb_sockets < MAX_LISTEN_SOCKETS)
	{
		listen_socket_t* listen_sock = &listen_sockets[nb_sockets];

		memset (listen_sock, 0, sizeof (*listen_sock));
		listen_sock->socket = INVALID_SOCKET;
		listen_sock->local_addr_name = local_addr_name;

		// Check if the address looks like a SCION address (ISD-ASN,IP)
		const char* comma = strchr (local_addr_name, ',');
		if (comma && comma[1] != '\0')
		{
			listen_sock->is_scion = true;
			listen_sock->local_addr_name = &comma[1];
		}

		nb_sockets++;
		return true;
	}
	else
		Com_Printf (MSG_ERROR,
					"> ERROR: too many listening addresses (max: %d)\n",
					MAX_LISTEN_SOCKETS);

	return false;
}


/*
====================
Sys_ResolveListenAddresses

Step 2 - Resolve the address names of all the listening sockets
====================
*/
qboolean Sys_ResolveListenAddresses (void)
{
	char local_addr[MAX_UNIX_SOCK_ADDR_LEN] = {0};

	// If nothing to resolve, add the local IPv4 & IPv6 addresses
	if (nb_sockets == 0)
	{
		const sa_family_t addr_families [] = { AF_INET, AF_INET6 };
		const unsigned int nb_addrs = sizeof (addr_families) / sizeof (addr_families[0]);
		unsigned int addr_ind;

		memset (listen_sockets, 0, sizeof (listen_sockets[0]) * nb_addrs);

		for (addr_ind = 0; addr_ind < nb_addrs; addr_ind++)
		{
			if (! Sys_BuildSockaddr (NULL, NULL, addr_families[addr_ind],
									 &listen_sockets[addr_ind].local_addr,
									 &listen_sockets[addr_ind].local_addr_len))
				return false;

			listen_sockets[addr_ind].optional = true;
			nb_sockets++;
		}

		// SCION socket that will bind to "default" IP
		listen_sockets[nb_sockets].is_scion = true;

		snprintf(local_addr, sizeof(local_addr), UNIX_SOCK_LOC_TEMPLATE, getpid(), nb_sockets);
		if (! Sys_BuildUnixSockaddr (local_addr,
									&listen_sockets[nb_sockets].local_addr,
									&listen_sockets[nb_sockets].local_addr_len))
			return false;

		nb_sockets++;
	}
	else
	{
		unsigned int sock_ind;

		for (sock_ind = 0; sock_ind < nb_sockets; sock_ind++)
		{
			listen_socket_t* listen_sock = &listen_sockets[sock_ind];

			if (! listen_sock->is_scion)
			{
				if (! Sys_StringToSockaddr (listen_sock->local_addr_name,
											&listen_sock->local_addr,
											&listen_sock->local_addr_len))
					return false;
			}
			else
			{
				snprintf(local_addr, sizeof(local_addr), UNIX_SOCK_LOC_TEMPLATE, getpid(), sock_ind);
				if (! Sys_BuildUnixSockaddr (local_addr,
											 &listen_sock->local_addr,
											 &listen_sock->local_addr_len))
					return false;
			}
		}
	}

	return true;
}


/*
====================
Sys_CreateListenSockets

Step 3 - Create the listening sockets
====================
*/
qboolean Sys_CreateListenSockets (void)
{
	for (unsigned int sock_ind = 0; sock_ind < nb_sockets; sock_ind++)
	{
		listen_socket_t* listen_sock = &listen_sockets[sock_ind];
		if (! listen_sock->is_scion)
		{
			if (! Sys_CreateIpListenSocket (listen_sock, &sock_ind))
			{
				Sys_CloseAllSockets ();
				return false;
			}
		}
		else
		{
			if (! Sys_CreateScionListenSocket (listen_sock, &sock_ind))
			{
				Sys_CloseAllSockets ();
				return false;
			}
		}
	}

	return true;
}


// ---------- Public functions (the rest) ---------- //

/*
====================
Sys_Cmdline_Option

Parse a system-dependent command line option
====================
*/
cmdline_status_t Sys_Cmdline_Option (const cmdlineopt_t* opt, const char** params, unsigned int nb_params)
{
#ifndef WIN32

	const char* opt_name;

	opt_name = opt->long_name;

	// Daemon mode
	if (strcmp (opt_name, "daemon") == 0)
		daemon_state = DAEMON_STATE_REQUEST;

	// Jail path
	else if (strcmp (opt_name, "jail-path") == 0)
		jail_path = params[0];

	// Low privileges user
	else if (strcmp (opt_name, "user") == 0)
		low_priv_user = params[0];

	return CMDLINE_STATUS_OK;

#else

	assert (false);  // We should never be here
	return CMDLINE_STATUS_INVALID_OPT;

#endif
}


/*
====================
Sys_UnsecureInit

System dependent initializations (called BEFORE security initializations)
====================
*/
qboolean Sys_UnsecureInit (void)
{
#ifdef WIN32
	WSADATA winsockdata;

	if (WSAStartup (MAKEWORD (1, 1), &winsockdata))
	{
		Com_Printf (MSG_ERROR, "> ERROR: can't initialize winsocks\n");
		return false;
	}
#endif

	return true;
}


/*
====================
Sys_SecurityInit

System dependent security initializations
====================
*/
qboolean Sys_SecurityInit (void)
{
#ifndef WIN32
	// If we will run as a daemon, we need to open /dev/null before chrooting
	if (daemon_state == DAEMON_STATE_REQUEST)
	{
		null_device = open ("/dev/null", O_RDWR, 0);
		if (null_device == -1)
		{
			Com_Printf (MSG_ERROR, "> ERROR: can't open /dev/null\n");
			return false;
		}
	}

	// UNIX allows us to be completely paranoid, so let's go for it
	if (geteuid () == 0)
	{
		struct passwd* pw;

		Com_Printf (MSG_WARNING,
					"> WARNING: running with super-user privileges\n");

		// We must get the account infos before the calls to chroot and chdir
		pw = getpwnam (low_priv_user);
		if (pw == NULL)
		{
			Com_Printf (MSG_ERROR, "> ERROR: can't get user \"%s\" properties\n",
						low_priv_user);
			return false;
		}

		// Chroot ourself
		if (chroot (jail_path) || chdir ("/"))
		{
			Com_Printf (MSG_ERROR,
						"  - ERROR: can't chroot myself to %s (%s)\n",
						jail_path, strerror (errno));
			return false;
		}
		Com_Printf (MSG_NORMAL, "  - Chrooted myself to %s\n", jail_path);

		// Switch to lower privileges
		if (setgid (pw->pw_gid) || setuid (pw->pw_uid))
		{
			Com_Printf (MSG_ERROR,
						"  - ERROR: can't switch to user \"%s\" privileges (%s)\n",
						low_priv_user, strerror (errno));
			return false;
		}
		Com_Printf (MSG_NORMAL,
					"  - Switched to user \"%s\" privileges (UID: %d, GID: %d)\n",
					low_priv_user, (int)pw->pw_uid, (int)pw->pw_gid);

		Com_Printf (MSG_NORMAL, "\n");
	}
#endif

	return true;
}


/*
====================
Sys_SecureInit

System dependent initializations (called AFTER security initializations)
====================
*/
qboolean Sys_SecureInit (void)
{
#ifndef WIN32
	// Should we run as a daemon?
	if (daemon_state == DAEMON_STATE_REQUEST)
	{
		if (daemon (0, 1) != 0)
		{
			Com_Printf (MSG_ERROR, "> ERROR: daemonization failed (%s)\n",
						strerror (errno));

			daemon_state = DAEMON_STATE_NO;
			return false;
		}

		// Replace the standard input and outputs by /dev/null
		assert (null_device != -1);
		dup2 (null_device, STDIN_FILENO);
		dup2 (null_device, STDOUT_FILENO);
		dup2 (null_device, STDERR_FILENO);

		// We no longer need to keep this file descriptor open
		close (null_device);
		null_device = -1;

		daemon_state = DAEMON_STATE_EFFECTIVE;
	}
#endif

	return true;
}


/*
====================
Sys_SockaddrToString

Returns a pointer to its static character buffer (do NOT free it!)
====================
*/
const char* Sys_SockaddrToString (const struct sockaddr_storage* address, socklen_t socklen)
{
	static char result [NI_MAXHOST + NI_MAXSERV];
	char port_str [NI_MAXSERV];
	int err;
	size_t res_len = 0;

	if (address->ss_family == AF_INET6)
	{
		result[res_len] = '[';
		res_len += 1;
	}

	err = getnameinfo((struct sockaddr*)address, socklen,
					  result + res_len, sizeof(result) - res_len,
					  port_str, sizeof(port_str),
					  NI_NUMERICHOST|NI_NUMERICSERV);
	if (err == 0)
	{
		const char* suffix = (address->ss_family == AF_INET6 ? "]" : "");

		res_len = strlen (result);
		snprintf (result + res_len, sizeof (result) - res_len, "%s:%s", suffix,
				  port_str);
	}
	else
	{
		Com_Printf (MSG_WARNING,
					"> WARNING: can't convert address to a printable form: %s\n",
					gai_strerror(err));
		strncpy(result, "NON-PRINTABLE ADDRESS", sizeof (result) - 1);
	}
	result[sizeof(result) - 1] = '\0';

	return result;
}


/*
====================
Sys_AddrToString

Returns a pointer to its static character buffer (do NOT free it!)
====================
*/
const char* Sys_AddrToString (const address_t* address, addr_len_t socklen)
{
	static char result [128];

	if (address->type == ADDR_TYPE_IP)
	{
		return Sys_SockaddrToString(&address->sock_addr, socklen);
	}
	else
	{
		assert (address->type == ADDR_TYPE_SCION);
		ssize_t offset = 0;
		ssize_t len = sizeof(result);

		uint64_t ia = address->scion_addr.ia;
		int ret = snprintf (result, len, "%hu-%hx:%hx:%hx,",
							ntohs(ia & 0xffff),
							ntohs((ia >> 16) & 0xffff),
							ntohs((ia >> 32) & 0xffff),
							ntohs((ia >> 48) & 0xffff));
		if (ret > 0) offset += ret;

		if (address->scion_addr.ip_family == AF_INET)
		{
			const unsigned char* ip = (const unsigned char*)&address->scion_addr.ipv4;
			ret = snprintf (result + offset, len - offset, "%hhu.%hhu.%hhu.%hhu",
							ip[0], ip[1], ip[2], ip[3]);
			if (ret > 0) offset += ret;
		}
		else
		{
			assert (address->scion_addr.ip_family == AF_INET6);
			const unsigned char* ip = (const unsigned char*)&address->scion_addr.ipv6;
			ret = snprintf (result + offset, len - offset,
							"[%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx]",
							ntohs(*(uint16_t*)&ip[ 0]), ntohs(*(uint16_t*)&ip[ 2]),
							ntohs(*(uint16_t*)&ip[ 4]), ntohs(*(uint16_t*)&ip[ 6]),
							ntohs(*(uint16_t*)&ip[ 8]), ntohs(*(uint16_t*)&ip[10]),
							ntohs(*(uint16_t*)&ip[12]), ntohs(*(uint16_t*)&ip[14]));
			if (ret > 0) offset += ret;
		}

		snprintf (result + offset, len - offset, ":%hu", address->scion_addr.port);

		return result;
	}
}


/*
====================
Sys_GetSockaddrPort

Get the network port from a sockaddr
====================
*/
unsigned short Sys_GetAddrPort (const address_t* address)
{
	if (address->type == ADDR_TYPE_SCION)
	{
		return ntohs((unsigned short)address->scion_addr.port);
	}
	else if (address->sock_addr.ss_family == AF_INET6)
	{
		assert (address->type == ADDR_TYPE_IP);

		const struct sockaddr_in6* addr_v6;

		addr_v6 = (const struct sockaddr_in6*)&address->sock_addr;
		return ntohs (addr_v6->sin6_port);
	}
	else
	{
		assert (address->type == ADDR_TYPE_IP);

		const struct sockaddr_in* addr_v4;

		assert (address->sock_addr.ss_family == AF_INET);
		addr_v4 = (const struct sockaddr_in*)&address->sock_addr;
		return ntohs (addr_v4->sin_port);
	}
}


/*
====================
Sys_RecvFrom

Receive a packet from a socket or a PAN connection
====================
*/
ssize_t Sys_RecvFrom(const listen_socket_t *sock, void *restrict buf, size_t len,
					 address_t *restrict from, addr_len_t *restrict addr_len)
{
	if (! sock->is_scion)
	{
		from->type = ADDR_TYPE_IP;
		return recvfrom (sock->socket, buf, len, 0, (struct sockaddr*)&from->sock_addr, addr_len);
	}

	// Receive SCION packet
	if (len > 2048) len = 2048;
	char packet [PAN_ADDR_HDR_SIZE + len];

	ssize_t bytes = recv (sock->socket, packet, sizeof(packet), 0);
	if (bytes < PAN_ADDR_HDR_SIZE)
	{
		if (bytes >= 0)
		{
			Com_Printf (MSG_WARNING,
						"> WARNING: Received invalid header from PAN unix socket\n");
		}
		return bytes;
	}

	memcpy (buf, packet + PAN_ADDR_HDR_SIZE, bytes - PAN_ADDR_HDR_SIZE);

	// Parse proxy header
	from->type = ADDR_TYPE_SCION;
	from->scion_addr.ia = *(uint64_t*)packet;
	uint32_t addrLen = *(uint32_t*)&packet[8];
	if (addrLen == 4)
	{
		from->scion_addr.ip_family = AF_INET;
		from->scion_addr.ipv4 = *(uint32_t*)&packet[12];
	}
	else if (addrLen == 16)
	{
		from->scion_addr.ip_family = AF_INET6;
		for (size_t i = 0; i < 4; ++i)
			from->scion_addr.ipv6[i] = *(uint32_t*)&packet[12 + 4*i];
	}
	else
	{
		Com_Printf (MSG_WARNING,
					"> WARNING: Received invalid header from PAN unix socket\n");
		return -1;
	}
	from->scion_addr.port = *(uint16_t*)&packet[28];

	return bytes - PAN_ADDR_HDR_SIZE;
}


/*
====================
Sys_SendTo

Send a packet to an IP/UDP or SCION/UDP endpoint
====================
*/
ssize_t Sys_SendTo(const listen_socket_t *sock, const void *restrict buf, size_t len,
				   const address_t *restrict to, addr_len_t addr_len)
{
	if (! sock->is_scion)
	{
		assert (to->type == ADDR_TYPE_IP);
		return sendto (sock->socket, buf, len, 0, (struct sockaddr*)&to->sock_addr, addr_len);
	}

	// Send SCION packet
	if (len > 2048) len = 2048;
	char packet [PAN_ADDR_HDR_SIZE + len];

	// Write proxy header
	assert (to->type == ADDR_TYPE_SCION);
	*(uint64_t*)packet = to->scion_addr.ia;
	if (to->scion_addr.ip_family == AF_INET)
	{
		*(uint32_t*)&packet[8] = 4;
		*(uint32_t*)&packet[12] = to->scion_addr.ipv4;
	}
	else
	{
		assert (to->scion_addr.ip_family == AF_INET6);
		*(uint32_t*)&packet[8] = 16;
		for (size_t i = 0; i < 4; ++i)
			*(uint32_t*)&packet[12 + 4*i] = to->scion_addr.ipv6[i];
	}
	*(uint16_t*)&packet[28] = to->scion_addr.port;

	memcpy (packet + PAN_ADDR_HDR_SIZE, buf, len);

	ssize_t bytes = send (sock->socket, packet, PAN_ADDR_HDR_SIZE + len, 0);
	if (bytes < PAN_ADDR_HDR_SIZE)
		return -1;

    return bytes;
}


/*
====================
Sys_GetLastNetError

Get the last network error code
====================
*/
int Sys_GetLastNetError (void)
{
#ifdef WIN32
	return WSAGetLastError ();
#else
	return errno;
#endif
}


/*
====================
Sys_GetLastNetErrorString

Get the last network error string
====================
*/
const char* Sys_GetLastNetErrorString (void)
{
	int last_error = Sys_GetLastNetError ();

#ifndef WIN32
	return strerror (last_error);
#else
	switch (last_error)
	{
		case NETERR_AFNOSUPPORT:
			return "Address family not supported by protocol family";

		case NETERR_NOPROTOOPT:
			return "Bad protocol option";

		case NETERR_INTR:
			return "Blocking operation interrupted";

		default:
		{
			static char last_error_string [32];

			snprintf (last_error_string, sizeof (last_error_string),
					  "Unknown error (%d)", last_error);
			last_error_string[sizeof (last_error_string) - 1] = '\0';

			return last_error_string;
		}
	}
#endif
}
