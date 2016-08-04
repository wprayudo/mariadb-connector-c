#ifndef _ma_pvio_h_
#define _ma_pvio_h_
#define cio_defined

#ifdef HAVE_TLS
#include <ma_tls.h>
#else
#define MARIADB_TLS void
#endif

#define PVIO_SET_ERROR if (pvio->set_error) \
                        pvio->set_error

#define PVIO_READ_AHEAD_CACHE_SIZE 16384
#define PVIO_READ_AHEAD_CACHE_MIN_SIZE 2048
#define PVIO_EINTR_TRIES 2

struct st_ma_pvio_methods;
typedef struct st_ma_pvio_methods PVIO_METHODS;

#define IS_PVIO_ASYNC(a) \
  ((a)->mysql && (a)->mysql->options.extension && (a)->mysql->options.extension->async_context)

#define IS_PVIO_ASYNC_ACTIVE(a) \
  (IS_PVIO_ASYNC(a)&& (a)->mysql->options.extension->async_context->active)

#define IS_MYSQL_ASYNC(a) \
  ((a)->options.extension && (a)->options.extension->async_context)

#define IS_MYSQL_ASYNC_ACTIVE(a) \
  (IS_MYSQL_ASYNC(a)&& (a)->options.extension->async_context->active)

enum enum_pvio_timeout {
  PVIO_CONNECT_TIMEOUT= 0,
  PVIO_READ_TIMEOUT,
  PVIO_WRITE_TIMEOUT 
};

enum enum_pvio_io_event
{
  PVIO_IO_EVENT_READ,
  PVIO_IO_EVENT_WRITE,
  PVIO_IO_EVENT_CONNECT
};

enum enum_pvio_type {
  PVIO_TYPE_UNIXSOCKET= 0,
  PVIO_TYPE_SOCKET,
  PVIO_TYPE_NAMEDPIPE,
  PVIO_TYPE_SHAREDMEM,
};

enum enum_pvio_operation {
  PVIO_READ= 0,
  PVIO_WRITE=1
};

struct st_pvio_callback;
struct st_mysql;
typedef struct st_pvio_callback {
  void (*callback)(struct st_mysql *mysql, unsigned char *buffer, size_t size);
  struct st_pvio_callback *next;
} PVIO_CALLBACK;

struct st_ma_pvio {
  void *data;
  /* read ahead cache */
  unsigned char *cache;
  unsigned char *cache_pos;
  size_t cache_size;
  enum enum_pvio_type type;
  int timeout[3];
  int ssl_type;  /* todo: change to enum (ssl plugins) */
  MARIADB_TLS *ctls;
  struct st_mysql *mysql;
  PVIO_METHODS *methods;
  void (*set_error)(struct st_mysql *mysql, unsigned int error_nr, const char *sqlstate, const char *format, ...);
  void(*callback)(struct st_ma_pvio *pvio, char is_read, const char *buffer, size_t length);
};

typedef struct st_ma_pvio_cinfo
{
  const char *host;
  const char *unix_socket;
  int port;
  enum enum_pvio_type type;
  struct st_mysql *mysql;
} MA_PVIO_CINFO;

struct st_ma_pvio_methods
{
  char (*set_timeout)(struct st_ma_pvio *pvio, enum enum_pvio_timeout type, int timeout);
  int (*get_timeout)(struct st_ma_pvio *pvio, enum enum_pvio_timeout type);
  size_t (*read)(struct st_ma_pvio *pvio, unsigned char *buffer, size_t length);
  size_t (*async_read)(struct st_ma_pvio *pvio, unsigned char *buffer, size_t length);
  size_t (*write)(struct st_ma_pvio *pvio, const unsigned char *buffer, size_t length);
  size_t (*async_write)(struct st_ma_pvio *pvio, const unsigned char *buffer, size_t length);
  int (*wait_io_or_timeout)(struct st_ma_pvio *pvio, char is_read, int timeout);
  char (*blocking)(struct st_ma_pvio *pvio, char value, char *old_value);
  char (*connect)(struct st_ma_pvio *pvio, MA_PVIO_CINFO *cinfo);
  char (*close)(struct st_ma_pvio *pvio);
  int (*fast_send)(struct st_ma_pvio *pvio);
  int (*keepalive)(struct st_ma_pvio *pvio);
  char (*get_handle)(struct st_ma_pvio *pvio, void *handle);
  char (*is_blocking)(struct st_ma_pvio *pvio);
  char (*is_alive)(struct st_ma_pvio *pvio);
  char (*has_data)(struct st_ma_pvio *pvio, size_t *data_len);
  int(*shutdown)(struct st_ma_pvio *pvio);
};

/* Function prototypes */
struct st_ma_pvio *ma_pvio_init(MA_PVIO_CINFO *cinfo);
void ma_pvio_close(struct st_ma_pvio *pvio);
size_t ma_pvio_cache_read(struct st_ma_pvio *pvio, unsigned char *buffer, size_t length);
size_t ma_pvio_read(struct st_ma_pvio *pvio, unsigned char *buffer, size_t length);
size_t ma_pvio_write(struct st_ma_pvio *pvio, const unsigned char *buffer, size_t length);
int ma_pvio_get_timeout(struct st_ma_pvio *pvio, enum enum_pvio_timeout type);
char ma_pvio_set_timeout(struct st_ma_pvio *pvio, enum enum_pvio_timeout type, int timeout);
int ma_pvio_fast_send(struct st_ma_pvio *pvio);
int ma_pvio_keepalive(struct st_ma_pvio *pvio);
int ma_pvio_get_socket(struct st_ma_pvio *pvio);
char ma_pvio_is_blocking(struct st_ma_pvio *pvio);
char ma_pvio_blocking(struct st_ma_pvio *pvio, char block, char *previous_mode);
char ma_pvio_is_blocking(struct st_ma_pvio *pvio);
int ma_pvio_wait_io_or_timeout(struct st_ma_pvio *pvio, char is_read, int timeout);
char ma_pvio_connect(struct st_ma_pvio *pvio, MA_PVIO_CINFO *cinfo);
char ma_pvio_is_alive(struct st_ma_pvio *pvio);
char ma_pvio_get_handle(struct st_ma_pvio *pvio, void *handle);
char ma_pvio_has_data(struct st_ma_pvio *pvio, size_t *length);

#endif /* _ma_pvio_h_ */
