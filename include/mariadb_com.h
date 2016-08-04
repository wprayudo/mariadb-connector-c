/************************************************************************************
    Copyright (C) 2000, 2012 MySQL AB & MySQL Finland AB & TCX DataKonsult AB,
                 Monty Program AB
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc., 
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA

   Part of this code includes code from the PHP project which
   is freely available from http://www.php.net
*************************************************************************************/

/*
** Common definition between mysql server & client
*/

#ifndef _mysql_com_h
#define _mysql_com_h


#define NAME_CHAR_LEN   64
#define NAME_LEN	192		/* Field/table name length */
#define SYSTEM_CHARSET_MBMAXLEN 3
#define HOSTNAME_LENGTH 60
#define SYSTEM_MB_MAX_CHAR_LENGTH 4
#define USERNAME_CHAR_LENGTH 128
#define USERNAME_LENGTH USERNAME_CHAR_LENGTH * SYSTEM_MB_MAX_CHAR_LENGTH
#define SERVER_VERSION_LENGTH 60
#define SQLSTATE_LENGTH 5
#define SCRAMBLE_LENGTH 20
#define SCRAMBLE_LENGTH_323 8
#define DEFINER_CHAR_LENGTH     (USERNAME_CHAR_LENGTH + HOSTNAME_LENGTH + 1)
#define DEFINER_LENGTH          (USERNAME_LENGTH + HOSTNAME_LENGTH + 1)
/*
  USER_HOST_BUFF_SIZE -- length of string buffer, that is enough to contain
  username and hostname parts of the user identifier with trailing zero in
  MySQL standard format:
  user_name_part@host_name_part\0
*/
#define USER_HOST_BUFF_SIZE HOSTNAME_LENGTH + USERNAME_LENGTH + 2

#define LOCAL_HOST	"localhost"
#define LOCAL_HOST_NAMEDPIPE "."

#if defined(_WIN32) && !defined( _CUSTOMCONFIG_)
#define MARIADB_NAMEDPIPE "MySQL"
#define MYSQL_SERVICENAME "MySql"
#endif /* _WIN32 */

/* for use in mysql client tools only */
#define MYSQL_AUTODETECT_CHARSET_NAME "auto"
#define BINCMP_FLAG       131072
#define GET_FIXED_FIELDS_FLAG (1 << 18) /* Used to get fields in item tree */
#define FIELD_IN_PART_FUNC_FLAG (1 << 19)/* Field part of partition func */

enum mysql_enum_shutdown_level {
  SHUTDOWN_DEFAULT = 0,
  SHUTDOWN_WAIT_CONNECTIONS= (unsigned char)(1 << 0),
  SHUTDOWN_WAIT_TRANSACTIONS= (unsigned char)(1 << 1),
  SHUTDOWN_WAIT_UPDATES= (unsigned char)(1 << 3),
  SHUTDOWN_WAIT_ALL_BUFFERS= ((unsigned char)(1 << 3) << 1),
  SHUTDOWN_WAIT_CRITICAL_BUFFERS= ((unsigned char)(1 << 3) << 1) + 1
};

enum enum_server_command
{
  COM_SLEEP = 0,
  COM_QUIT,
  COM_INIT_DB,
  COM_QUERY,
  COM_FIELD_LIST,
  COM_CREATE_DB,
  COM_DROP_DB,
  COM_REFRESH,
  COM_SHUTDOWN,
  COM_STATISTICS,
  COM_PROCESS_INFO,
  COM_CONNECT,
  COM_PROCESS_KILL,
  COM_DEBUG,
  COM_PING,
  COM_TIME = 15,
  COM_DELAYED_INSERT,
  COM_CHANGE_USER,
  COM_BINLOG_DUMP,
  COM_TABLE_DUMP,
  COM_CONNECT_OUT = 20,
  COM_REGISTER_SLAVE,
  COM_STMT_PREPARE = 22,
  COM_STMT_EXECUTE = 23,
  COM_STMT_SEND_LONG_DATA = 24,
  COM_STMT_CLOSE = 25,
  COM_STMT_RESET = 26,
  COM_SET_OPTION = 27,
  COM_STMT_FETCH = 28,
  COM_DAEMON,
  COM_MDB_GAP_BEG,
  COM_MDB_GAP_END=253,
  COM_MULTI = 254,
  COM_END
};

/*
  Length of random string sent by server on handshake; this is also length of
  obfuscated password, received from client
*/
#define SCRAMBLE_LENGTH 20
#define SCRAMBLE_LENGTH_323 8
/* length of password stored in the db: new passwords are preceeded with '*' */
#define SCRAMBLED_PASSWORD_CHAR_LENGTH (SCRAMBLE_LENGTH*2+1)
#define SCRAMBLED_PASSWORD_CHAR_LENGTH_323 (SCRAMBLE_LENGTH_323*2)


#define NOT_NULL_FLAG	1		/* Field can't be NULL */
#define PRI_KEY_FLAG	2		/* Field is part of a primary key */
#define UNIQUE_KEY_FLAG 4		/* Field is part of a unique key */
#define MULTIPLE_KEY_FLAG 8		/* Field is part of a key */
#define BLOB_FLAG	16		/* Field is a blob */
#define UNSIGNED_FLAG	32		/* Field is unsigned */
#define ZEROFILL_FLAG	64		/* Field is zerofill */
#define BINARY_FLAG	128
/* The following are only sent to new clients */
#define ENUM_FLAG	256		/* field is an enum */
#define AUTO_INCREMENT_FLAG 512		/* field is a autoincrement field */
#define TIMESTAMP_FLAG	1024		/* Field is a timestamp */
#define SET_FLAG	2048		/* field is a set */
/* new since 3.23.58 */
#define NO_DEFAULT_VALUE_FLAG 4096	/* Field doesn't have default value */
#define ON_UPDATE_NOW_FLAG 8192         /* Field is set to NOW on UPDATE */
/* end new */
#define NUM_FLAG	32768		/* Field is num (for clients) */
#define PART_KEY_FLAG	16384		/* Intern; Part of some key */
#define GROUP_FLAG	32768		/* Intern: Group field */
#define UNIQUE_FLAG	65536		/* Intern: Used by sql_yacc */

/**
  Intern: Field in TABLE object for new version of altered table,
  which participates in a newly added index.
*/
#define FIELD_IN_ADD_INDEX (1 << 20)
#define FIELD_IS_RENAMED (1<< 21)       /* Intern: Field is being renamed */
#define FIELD_FLAGS_STORAGE_MEDIA 22    /* Field storage media, bit 22-23 */
#define FIELD_FLAGS_STORAGE_MEDIA_MASK (3 << FIELD_FLAGS_STORAGE_MEDIA)
#define FIELD_FLAGS_COLUMN_FORMAT 24    /* Field column format, bit 24-25 */
#define FIELD_FLAGS_COLUMN_FORMAT_MASK (3 << FIELD_FLAGS_COLUMN_FORMAT)
#define FIELD_IS_DROPPED (1<< 26)       /* Intern: Field is being dropped */
#define HAS_EXPLICIT_VALUE (1 << 27)    /* An INSERT/UPDATE operation supplied an explicit default value */

#define REFRESH_GRANT           (1ULL << 0)  /* Refresh grant tables */
#define REFRESH_LOG             (1ULL << 1)  /* Start on new log file */
#define REFRESH_TABLES          (1ULL << 2)  /* close all tables */
#define REFRESH_HOSTS           (1ULL << 3)  /* Flush host cache */
#define REFRESH_STATUS          (1ULL << 4)  /* Flush status variables */
#define REFRESH_THREADS         (1ULL << 5)  /* Flush thread cache */
#define REFRESH_SLAVE           (1ULL << 6)  /* Reset master info and restart slave
thread */
#define REFRESH_MASTER          (1ULL << 7)  /* Remove all bin logs in the index
and truncate the index */

/* The following can't be set with mysql_refresh() */
#define REFRESH_ERROR_LOG       (1ULL << 8)  /* Rotate only the erorr log */
#define REFRESH_ENGINE_LOG      (1ULL << 9)  /* Flush all storage engine logs */
#define REFRESH_BINARY_LOG      (1ULL << 10) /* Flush the binary log */
#define REFRESH_RELAY_LOG       (1ULL << 11) /* Flush the relay log */
#define REFRESH_GENERAL_LOG     (1ULL << 12) /* Flush the general log */
#define REFRESH_SLOW_LOG        (1ULL << 13) /* Flush the slow query log */

#define REFRESH_READ_LOCK       (1ULL << 14) /* Lock tables for read */
#define REFRESH_CHECKPOINT      (1ULL << 15) /* With REFRESH_READ_LOCK: block checkpoints too */

#define REFRESH_QUERY_CACHE     (1ULL << 16) /* clear the query cache */
#define REFRESH_QUERY_CACHE_FREE (1ULL << 17) /* pack query cache */
#define REFRESH_DES_KEY_FILE    (1ULL << 18)
#define REFRESH_USER_RESOURCES  (1ULL << 19)
#define REFRESH_FOR_EXPORT      (1ULL << 20) /* FLUSH TABLES ... FOR EXPORT */

#define REFRESH_GENERIC         (1ULL << 30)
#define REFRESH_FAST            (1ULL << 31) /* Intern flag */

#define CLIENT_MYSQL                1
#define CLIENT_FOUND_ROWS	    2	/* Found instead of affected rows */
#define CLIENT_LONG_FLAG	    4	/* Get all column flags */
#define CLIENT_CONNECT_WITH_DB	    8	/* One can specify db on connect */
#define CLIENT_NO_SCHEMA	   16	/* Don't allow database.table.column */
#define CLIENT_COMPRESS		   32	/* Can use compression protocol */
#define CLIENT_ODBC		   64	/* Odbc client */
#define CLIENT_LOCAL_FILES	  128	/* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE	  256	/* Ignore spaces before '(' */
#define CLIENT_INTERACTIVE	  1024	/* This is an interactive client */
#define CLIENT_SSL                2048     /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE     4096     /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS	  8192	/* Client knows about transactions */
/* added in 4.x */
#define CLIENT_PROTOCOL_41         512
#define CLIENT_RESERVED          16384
#define CLIENT_SECURE_CONNECTION 32768  
#define CLIENT_MULTI_STATEMENTS  (1UL << 16)
#define CLIENT_MULTI_RESULTS     (1UL << 17)
#define CLIENT_PS_MULTI_RESULTS  (1UL << 18)
#define CLIENT_PLUGIN_AUTH       (1UL << 19)
#define CLIENT_CONNECT_ATTRS     (1UL << 20)
/* Enable authentication response packet to be larger than 255 bytes. */
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA (1UL << 21)
/* Don't close the connection for a connection with expired password. */
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS (1UL << 22)
#define CLIENT_SESSION_TRACKING  (1UL << 23)

#define CLIENT_PROGRESS          (1UL << 29) /* client supports progress indicator */
#define CLIENT_PROGRESS_OBSOLETE  CLIENT_PROGRESS 

#define CLIENT_SSL_VERIFY_SERVER_CERT (1UL << 30)
#define CLIENT_REMEMBER_OPTIONS  (1UL << 31)

/* MariaDB specific capabilities */
#define MARIADB_CLIENT_FLAGS 0xFFFFFFFF00000000ULL
#define MARIADB_CLIENT_PROGRESS (1ULL << 32)
#define MARIADB_CLIENT_COM_MULTI (1ULL << 33)
//#define MARIADB_CLIENT_EXTENDED_FLAGS (1ULL << 63)

#define MARIADB_CLIENT_SUPPORTED_FLAGS (MARIADB_CLIENT_PROGRESS |\
                                       MARIADB_CLIENT_COM_MULTI)

#define CLIENT_SUPPORTED_FLAGS  (CLIENT_MYSQL |\
                                 CLIENT_FOUND_ROWS |\
                                 CLIENT_LONG_FLAG |\
                                 CLIENT_CONNECT_WITH_DB |\
                                 CLIENT_NO_SCHEMA |\
                                 CLIENT_COMPRESS |\
                                 CLIENT_ODBC |\
                                 CLIENT_LOCAL_FILES |\
                                 CLIENT_IGNORE_SPACE |\
                                 CLIENT_INTERACTIVE |\
                                 CLIENT_SSL |\
                                 CLIENT_IGNORE_SIGPIPE |\
                                 CLIENT_TRANSACTIONS |\
                                 CLIENT_PROTOCOL_41 |\
                                 CLIENT_RESERVED |\
                                 CLIENT_SECURE_CONNECTION |\
                                 CLIENT_MULTI_STATEMENTS |\
                                 CLIENT_MULTI_RESULTS |\
                                 CLIENT_PROGRESS |\
		                 CLIENT_SSL_VERIFY_SERVER_CERT |\
                                 CLIENT_REMEMBER_OPTIONS |\
                                 CLIENT_PLUGIN_AUTH |\
                                 CLIENT_SESSION_TRACKING |\
                                 CLIENT_CONNECT_ATTRS)

#define CLIENT_CAPABILITIES	(CLIENT_MYSQL | \
                                 CLIENT_LONG_FLAG |\
                                 CLIENT_TRANSACTIONS |\
                                 CLIENT_SECURE_CONNECTION |\
                                 CLIENT_MULTI_RESULTS | \
                                 CLIENT_PS_MULTI_RESULTS |\
                                 CLIENT_PROTOCOL_41 |\
                                 CLIENT_PLUGIN_AUTH |\
                                 CLIENT_SESSION_TRACKING |\
                                 CLIENT_CONNECT_ATTRS)

#define CLIENT_DEFAULT_FLAGS ((CLIENT_SUPPORTED_FLAGS & ~CLIENT_COMPRESS)\
                                                      & ~CLIENT_SSL)

/*
  Gather all possible capabilites (flags) supported by the server

  MARIADB_* flags supported only by MariaDB connector(s).
*/
#define CLIENT_ALL_FLAGS  (\
                           CLIENT_FOUND_ROWS | \
                           CLIENT_LONG_FLAG | \
                           CLIENT_CONNECT_WITH_DB | \
                           CLIENT_NO_SCHEMA | \
                           CLIENT_COMPRESS | \
                           CLIENT_ODBC | \
                           CLIENT_LOCAL_FILES | \
                           CLIENT_IGNORE_SPACE | \
                           CLIENT_PROTOCOL_41 | \
                           CLIENT_INTERACTIVE | \
                           CLIENT_SSL | \
                           CLIENT_IGNORE_SIGPIPE | \
                           CLIENT_TRANSACTIONS | \
                           CLIENT_RESERVED | \
                           CLIENT_SECURE_CONNECTION | \
                           CLIENT_MULTI_STATEMENTS | \
                           CLIENT_MULTI_RESULTS | \
                           CLIENT_PS_MULTI_RESULTS | \
                           CLIENT_SSL_VERIFY_SERVER_CERT | \
                           CLIENT_REMEMBER_OPTIONS | \
                           MARIADB_CLIENT_PROGRESS | \
                           CLIENT_PLUGIN_AUTH | \
                           CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | \
                           CLIENT_CONNECT_ATTRS |\
                           MARIADB_CLIENT_COM_MULTI)

/*
  To be added later:
  CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
*/

/*
  Switch off the flags that are optional and depending on build flags
  If any of the optional flags is supported by the build it will be switched
  on before sending to the client during the connection handshake.
*/
#define CLIENT_BASIC_FLAGS (((CLIENT_ALL_FLAGS & ~CLIENT_SSL) \
                                               & ~CLIENT_COMPRESS) \
                                               & ~CLIENT_SSL_VERIFY_SERVER_CERT)

#ifdef HAVE_COMPRESS
#define CAN_CLIENT_COMPRESS CLIENT_COMPRESS
#else
#define CAN_CLIENT_COMPRESS 0
#endif

#define SERVER_STATUS_IN_TRANS               1	/* Transaction has started */
#define SERVER_STATUS_AUTOCOMMIT             2	/* Server in auto_commit mode */
#define SERVER_MORE_RESULTS_EXIST            8
#define SERVER_QUERY_NO_GOOD_INDEX_USED     16
#define SERVER_QUERY_NO_INDEX_USED          32
#define SERVER_STATUS_CURSOR_EXISTS         64
#define SERVER_STATUS_LAST_ROW_SENT        128
#define SERVER_STATUS_DB_DROPPED           256 
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES 512
#define SERVER_STATUS_METADATA_CHANGED    1024
#define SERVER_QUERY_WAS_SLOW             2048
#define SERVER_PS_OUT_PARAMS              4096

#define CLIENT_MULTI_QUERIES    CLIENT_MULTI_STATEMENTS 
#define SERVER_MORE_RESULTS_EXISTS       SERVER_MORE_RESULTS_EXIST

/**
  Set at the same time as SERVER_STATUS_IN_TRANS if the started
  multi-statement transaction is a read-only transaction. Cleared
  when the transaction commits or aborts. Since this flag is sent
  to clients in OK and EOF packets, the flag indicates the
  transaction status at the end of command execution.
*/
#define SERVER_STATUS_IN_TRANS_READONLY 8192


/**
  Server status flags that must be cleared when starting
  execution of a new SQL statement.
  Flags from this set are only added to the
  current server status by the execution engine, but
  never removed -- the execution engine expects them
  to disappear automagically by the next command.
*/
#define SERVER_STATUS_CLEAR_SET (SERVER_QUERY_NO_GOOD_INDEX_USED| \
                                 SERVER_QUERY_NO_INDEX_USED|\
                                 SERVER_MORE_RESULTS_EXISTS|\
                                 SERVER_STATUS_METADATA_CHANGED |\
                                 SERVER_QUERY_WAS_SLOW |\
                                 SERVER_STATUS_DB_DROPPED |\
                                 SERVER_STATUS_CURSOR_EXISTS|\
                                 SERVER_STATUS_LAST_ROW_SENT)
#define SERVER_SESSION_STATE_CHANGED      (1UL << 14)

#define MYSQL_ERRMSG_SIZE	512
#define NET_READ_TIMEOUT	30		/* Timeout on read */
#define NET_WRITE_TIMEOUT	60		/* Timeout on write */
#define NET_WAIT_TIMEOUT	8*60*60		/* Wait for new query */

/* for server integration (mysqlbinlog) */
#define LIST_PROCESS_HOST_LEN 64
#define MYSQL50_TABLE_NAME_PREFIX         "#mysql50#"
#define MYSQL50_TABLE_NAME_PREFIX_LENGTH  (sizeof(MYSQL50_TABLE_NAME_PREFIX)-1)
#define SAFE_NAME_LEN (NAME_LEN + MYSQL50_TABLE_NAME_PREFIX_LENGTH)

struct st_ma_pvio;
typedef struct st_ma_pvio MARIADB_PVIO;

#define MAX_CHAR_WIDTH		255	/* Max length for a CHAR colum */
#define MAX_BLOB_WIDTH		8192	/* Default width for blob */

/* the following defines were added for PHP's mysqli and pdo extensions: 
   see: CONC-56
*/
#define MAX_TINYINT_WIDTH     3
#define MAX_SMALLINT_WIDTH    5
#define MAX_MEDIUMINT_WIDTH   8
#define MAX_INT_WIDTH        10
#define MAX_BIGINT_WIDTH     20

struct st_ma_connection_plugin;


typedef struct st_ma_net {
  MARIADB_PVIO *pvio;
  unsigned char *buff;
  unsigned char *buff_end,*write_pos,*read_pos;
  my_socket fd;					/* For Perl DBI/dbd */
  unsigned long remain_in_buf,length;
  unsigned long buf_length, where_b;
  unsigned long max_packet, max_packet_size;
  unsigned int pkt_nr, compress_pkt_nr;
  unsigned int write_timeout, read_timeout, retry_count;
  int fcntl;
  unsigned int *return_status;
  unsigned char reading_or_writing;
  char save_char;
  char unused_1;
  my_bool unused_2;
  my_bool compress;
  my_bool unused_3;
  void *unused_4;
  unsigned int last_errno;
  unsigned char error;
  my_bool unused_5;
  my_bool unused_6;
  char last_error[MYSQL_ERRMSG_SIZE];
  char sqlstate[SQLSTATE_LENGTH+1];
  struct st_mariadb_net_extension *extension;
} MA_NET;

struct st_vio;
typedef struct st_vio Vio;

typedef struct st_net {
#if !defined(CHECK_EMBEDDED_DIFFERENCES) || !defined(EMBEDDED_LIBRARY)
  Vio *vio;
  unsigned char *buff, *buff_end, *write_pos, *read_pos;
  my_socket fd;					/* For Perl DBI/dbd */
  /*
  The following variable is set if we are doing several queries in one
  command ( as in LOAD TABLE ... FROM MASTER ),
  and do not want to confuse the client with OK at the wrong time
  */
  unsigned long remain_in_buf, length, buf_length, where_b;
  unsigned long max_packet, max_packet_size;
  unsigned int pkt_nr, compress_pkt_nr;
  unsigned int write_timeout, read_timeout, retry_count;
  int fcntl;
  unsigned int *return_status;
  unsigned char reading_or_writing;
  char save_char;
  char net_skip_rest_factor;
  my_bool thread_specific_malloc;
  my_bool compress;
  my_bool unused3; /* Please remove with the next incompatible ABI change. */
  /*
  Pointer to query object in query cache, do not equal NULL (0) for
  queries in cache that have not stored its results yet
  */
#endif
  void *thd; 	   /* Used by MariaDB server to avoid calling current_thd */
  unsigned int last_errno;
  unsigned char error;
  my_bool unused4; /* Please remove with the next incompatible ABI change. */
  my_bool unused5; /* Please remove with the next incompatible ABI change. */
  /** Client library error message buffer. Actually belongs to struct MYSQL. */
  char last_error[MYSQL_ERRMSG_SIZE];
  /** Client library sqlstate buffer. Set along with the error message. */
  char sqlstate[SQLSTATE_LENGTH + 1];
  void *extension;
} NET;

#define packet_error ((unsigned int) -1)

/* used by mysql_set_server_option */
enum enum_mysql_set_option
{
  MYSQL_OPTION_MULTI_STATEMENTS_ON,
  MYSQL_OPTION_MULTI_STATEMENTS_OFF
};

enum enum_session_state_type
{
  SESSION_TRACK_SYSTEM_VARIABLES= 0,
  SESSION_TRACK_SCHEMA,
  SESSION_TRACK_STATE_CHANGE,
  /* currently not supported by MariaDB Server */
  SESSION_TRACK_GTIDS,
  SESSION_TRACK_TRANSACTION_CHARACTERISTICS,
  SESSION_TRACK_TRANSACTION_TYPE /* make sure that SESSION_TRACK_END always points
                                    to last element of enum !! */
};

#define SESSION_TRACK_BEGIN 0
#define SESSION_TRACK_END SESSION_TRACK_TRANSACTION_TYPE
#define SESSION_TRACK_TYPES SESSION_TRACK_END + 1

enum enum_field_types { MYSQL_TYPE_DECIMAL, MYSQL_TYPE_TINY,
                        MYSQL_TYPE_SHORT,  MYSQL_TYPE_LONG,
                        MYSQL_TYPE_FLOAT,  MYSQL_TYPE_DOUBLE,
                        MYSQL_TYPE_NULL,   MYSQL_TYPE_TIMESTAMP,
                        MYSQL_TYPE_LONGLONG,MYSQL_TYPE_INT24,
                        MYSQL_TYPE_DATE,   MYSQL_TYPE_TIME,
                        MYSQL_TYPE_DATETIME, MYSQL_TYPE_YEAR,
                        MYSQL_TYPE_NEWDATE, MYSQL_TYPE_VARCHAR,
                        MYSQL_TYPE_BIT,
                        /*
                          the following types are not used by client,
                          only for mysqlbinlog!!
                        */
                        MYSQL_TYPE_TIMESTAMP2,
                        MYSQL_TYPE_DATETIME2,
                        MYSQL_TYPE_TIME2,
                        /* --------------------------------------------- */
                        MYSQL_TYPE_NEWDECIMAL=246,
                        MYSQL_TYPE_ENUM=247,
                        MYSQL_TYPE_SET=248,
                        MYSQL_TYPE_TINY_BLOB=249,
                        MYSQL_TYPE_MEDIUM_BLOB=250,
                        MYSQL_TYPE_LONG_BLOB=251,
                        MYSQL_TYPE_BLOB=252,
                        MYSQL_TYPE_VAR_STRING=253,
                        MYSQL_TYPE_STRING=254,
                        MYSQL_TYPE_GEOMETRY=255,
                        MAX_NO_FIELD_TYPES };

#define FIELD_TYPE_CHAR FIELD_TYPE_TINY		/* For compability */
#define FIELD_TYPE_INTERVAL FIELD_TYPE_ENUM	/* For compability */
#define FIELD_TYPE_DECIMAL MYSQL_TYPE_DECIMAL
#define FIELD_TYPE_NEWDECIMAL MYSQL_TYPE_NEWDECIMAL
#define FIELD_TYPE_TINY MYSQL_TYPE_TINY
#define FIELD_TYPE_SHORT MYSQL_TYPE_SHORT
#define FIELD_TYPE_LONG MYSQL_TYPE_LONG
#define FIELD_TYPE_FLOAT MYSQL_TYPE_FLOAT
#define FIELD_TYPE_DOUBLE MYSQL_TYPE_DOUBLE
#define FIELD_TYPE_NULL MYSQL_TYPE_NULL
#define FIELD_TYPE_TIMESTAMP MYSQL_TYPE_TIMESTAMP
#define FIELD_TYPE_LONGLONG MYSQL_TYPE_LONGLONG
#define FIELD_TYPE_INT24 MYSQL_TYPE_INT24
#define FIELD_TYPE_DATE MYSQL_TYPE_DATE
#define FIELD_TYPE_TIME MYSQL_TYPE_TIME
#define FIELD_TYPE_DATETIME MYSQL_TYPE_DATETIME
#define FIELD_TYPE_YEAR MYSQL_TYPE_YEAR
#define FIELD_TYPE_NEWDATE MYSQL_TYPE_NEWDATE
#define FIELD_TYPE_ENUM MYSQL_TYPE_ENUM
#define FIELD_TYPE_SET MYSQL_TYPE_SET
#define FIELD_TYPE_TINY_BLOB MYSQL_TYPE_TINY_BLOB
#define FIELD_TYPE_MEDIUM_BLOB MYSQL_TYPE_MEDIUM_BLOB
#define FIELD_TYPE_LONG_BLOB MYSQL_TYPE_LONG_BLOB
#define FIELD_TYPE_BLOB MYSQL_TYPE_BLOB
#define FIELD_TYPE_VAR_STRING MYSQL_TYPE_VAR_STRING
#define FIELD_TYPE_STRING MYSQL_TYPE_STRING
#define FIELD_TYPE_GEOMETRY MYSQL_TYPE_GEOMETRY
#define FIELD_TYPE_BIT MYSQL_TYPE_BIT

/* sql type stored in .frm files for virtual fields */
#define MYSQL_TYPE_VIRTUAL 245

extern unsigned long max_allowed_packet;
extern unsigned long net_buffer_length;

#define net_new_transaction(net) ((net)->pkt_nr=0)

int	ma_net_init(MA_NET *net, MARIADB_PVIO *pvio);
void	ma_net_end(MA_NET *net);
void	ma_net_clear(MA_NET *net);
int	ma_net_flush(MA_NET *net);
int	ma_net_write(MA_NET *net,const unsigned char *packet, size_t len);
int	ma_net_write_command(MA_NET *net,unsigned char command,const char *packet,
			  size_t len);
int	ma_net_real_write(MA_NET *net,const char *packet, size_t len);
extern unsigned long ma_net_read(MA_NET *net);

#ifdef MYSQL_SERVER
my_bool my_net_init(NET *net, Vio *vio, void *thd, uint my_flags);
void	net_end(NET *net);
void net_clear(NET *net, char);
my_bool	net_flush(NET *net);
my_bool	my_net_write(NET *net, const unsigned char *packet, size_t len);
ulong my_net_read(NET *net);
my_bool net_write_command(NET *net, uchar command, const uchar *header, size_t head_len, const uchar *packet, size_t len);
int	net_real_write(NET *net, const unsigned char *packet, size_t len);
void my_net_set_write_timeout(NET *net, uint timeout);
void my_net_set_read_timeout(NET *net, uint timeout);
extern unsigned long net_read(NET *net);
unsigned char *net_store_length(unsigned char *pkg, ulonglong length);
char *octet2hex(char *to, const char *str, unsigned int len);
ulong my_net_read_packet(NET *net, my_bool read_from_server);

void create_random_string(char *to, unsigned int length,
struct my_rnd_struct *rand_st);
my_bool check_scramble_323(const unsigned char *reply, const char *message,
  unsigned long *salt);
my_bool check_scramble(const unsigned char *reply, const char *message,
  const unsigned char *hash_stage2);
const char *mysql_errno_to_sqlstate(uint mysql_errno);
void get_salt_from_password_323(ulong *res, const char *password);
void get_salt_from_password(uint8 *hash_stage2, const char *password);
void create_random_string(char *to, uint length, struct my_rnd_struct *rand_st);
ulong STDCALL net_field_length(uchar **packet);
my_ulonglong net_field_length_ll(uchar **packet);
my_ulonglong safe_net_field_length_ll(uchar **packet, size_t packet_len);
uchar *net_store_length(uchar *pkg, ulonglong length);
uchar *safe_net_store_length(uchar *pkg, size_t pkg_len, ulonglong length);

#define MYSQL_NAMEDPIPE "MySQL"
#define RPL_VERSION_HACK "5.5.5-"
#endif





struct rand_struct {
  unsigned long seed1,seed2,max_value;
  double max_value_dbl;
};

  /* The following is for user defined functions */

enum Item_result { STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT, DECIMAL_RESULT, TIME_RESULT };


typedef struct st_udf_args
{
  unsigned int arg_count;		/* Number of arguments */
  enum Item_result *arg_type;		/* Pointer to item_results */
  char **args;				/* Pointer to argument */
  unsigned long *lengths;		/* Length of string arguments */
  char *maybe_null;			/* Set to 1 for all maybe_null args */
  char **attributes;                    /* Pointer to attribute name */
  unsigned long *attribute_lengths;     /* Length of attribute arguments */
  void *extension;
} UDF_ARGS;
  /* This holds information about the result */

typedef struct st_udf_init
{
  my_bool maybe_null;			/* 1 if function can return NULL */
  unsigned int decimals;		/* for real functions */
  unsigned int max_length;		/* For string functions */
  char	  *ptr;				/* free pointer for function data */
  my_bool const_item;			/* 0 if result is independent of arguments */
} UDF_INIT;

/* Connection types */
#define MARIADB_CONNECTION_UNIXSOCKET   0
#define MARIADB_CONNECTION_TCP          1
#define MARIADB_CONNECTION_NAMEDPIPE    2
#define MARIADB_CONNECTION_SHAREDMEM    3

  /* Constants when using compression */
#define NET_HEADER_SIZE 4		/* standard header size */
#define COMP_HEADER_SIZE 3		/* compression header extra size */



#ifdef __cplusplus
extern "C" {
#endif
  
char *ma_scramble_323(char *to,const char *message,const char *password);
void ma_scramble_41(const unsigned char *buffer, const char *scramble, const char *password);
void ma_hash_password(unsigned long *result, const char *password, size_t len);
void ma_make_scrambled_password(char *to,const char *password);

/* Some other useful functions */

void mariadb_load_defaults(const char *conf_file, const char **groups,
		   int *argc, char ***argv);
my_bool ma_thread_init(void);
void ma_thread_end(void);

#ifdef __cplusplus
}
#endif

#define NULL_LENGTH ((unsigned long) ~0) /* For net_store_length */
#define MYSQL_STMT_HEADER       4
#define MYSQL_LONG_DATA_HEADER  6
/*
  Maximum length of comments
*/
#define TABLE_COMMENT_INLINE_MAXLEN 180 /* pre 5.5: 60 characters */
#define TABLE_COMMENT_MAXLEN 2048
#define COLUMN_COMMENT_MAXLEN 1024
#define INDEX_COMMENT_MAXLEN 1024
#define TABLE_PARTITION_COMMENT_MAXLEN 1024


#endif
