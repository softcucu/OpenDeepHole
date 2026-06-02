#define PRODUCT_NULL PRODUCT_PLATFORM_NULL
#define MY_NULL_VALUE PRODUCT_NULL
#define NULL PRODUCT_NULL
#define INVALID_MSGBOX_ID -1
#define INIT_FAILED 1
#define RUNNING 2
#define FINISHED 3
#define MAX_BIP_MPDU 1497

struct Owner {
    char *buf;
    char *last;
};

struct RouterPort {
    int state;
    int port_id;
};

struct IpData {
    char *buff;
    int max_buff;
};

struct object_data {
    char *Object_Name;
};

typedef struct RouterPort ROUTER_PORT;
typedef struct IpData IP_DATA;
typedef int MSGBOX_ID;
typedef int bool;
typedef unsigned int uint32_t;

extern char *malloc(int size);
extern void free(void *ptr);
extern void release_buffer(char *ptr);
extern void consume(char *ptr);
extern int dl_ip_init(ROUTER_PORT *port, IP_DATA *ip_data);
extern void dl_ip_cleanup(IP_DATA *ip_data);
extern MSGBOX_ID create_msgbox(void);
extern void *Object_List;
extern struct object_data *Keylist_Data(void *list, uint32_t object_instance);
extern char *bacnet_strdup(const char *new_name);

int report_return_leak(int flag) {
    char *p = malloc(8);
    if (flag) {
        return -1;
    }
    free(p);
    return 0;
}

int report_branch_leak(int flag) {
    char *p = malloc(8);
    if (flag) {
        return -1;
    } else {
        free(p);
    }
    return 0;
}

int report_continue_leak(int bad) {
    for (;;) {
        char *q = malloc(16);
        if (q == PRODUCT_NULL) {
            continue;
        }
        if (bad) {
            continue;
        }
        release_buffer(q);
    }
}

int report_partial_multi(int flag) {
    char *p = malloc(8);
    char *q = malloc(16);
    if (flag) {
        free(p);
        return -1;
    }
    free(p);
    free(q);
    return 0;
}

int ok_null_macro_return(void) {
    char *p = malloc(8);
    if (p == PRODUCT_NULL) {
        return -1;
    }
    free(p);
    return 0;
}

int ok_init_failed_branch(void) {
    char *p = malloc(8);
    if (MY_NULL_VALUE == p) {
        return -1;
    }
    release_buffer(p);
    return 0;
}

int report_null_initialized_before_allocation(int flag) {
    char *p = PRODUCT_NULL;
    if (flag) {
        return -1;
    }
    p = malloc(8);
    release_buffer(p);
    return 0;
}

void *report_cleanup_object_early_returns(void *pArgs) {
    MSGBOX_ID msgboxid;
    ROUTER_PORT *port = (ROUTER_PORT *)pArgs;
    IP_DATA ip_data;

    if (!dl_ip_init(port, &ip_data)) {
        port->state = INIT_FAILED;
        return NULL;
    }

    ip_data.max_buff = MAX_BIP_MPDU;
    ip_data.buff = (char *)malloc(ip_data.max_buff);
    if (ip_data.buff == NULL) {
        port->state = INIT_FAILED;
        return NULL;
    }

    msgboxid = create_msgbox();
    if (msgboxid == INVALID_MSGBOX_ID) {
        port->state = INIT_FAILED;
        return NULL;
    }

    port->port_id = msgboxid;
    port->state = RUNNING;
    dl_ip_cleanup(&ip_data);
    port->state = FINISHED;
    return NULL;
}

int ok_param_transfer(char **out, int flag) {
    char *p = malloc(8);
    if (flag) {
        *out = p;
        return 0;
    }
    free(p);
    return 0;
}

int ok_param_member_transfer(struct Owner *owner, int flag) {
    char *p = malloc(8);
    if (flag) {
        owner->buf = p;
        return 0;
    }
    free(p);
    return 0;
}

int ok_member_base_null(struct Owner *owner) {
    if (owner == PRODUCT_NULL) {
        return -1;
    }
    release_buffer(owner->buf);
    return 0;
}

int ok_continue_null_branch(void) {
    for (;;) {
        char *q = malloc(16);
        if (q == PRODUCT_NULL) {
            continue;
        }
        release_buffer(q);
    }
}

int ok_continue_transfer(struct Owner *owner, int flag) {
    for (;;) {
        char *q = malloc(16);
        if (q == PRODUCT_NULL) {
            continue;
        }
        if (flag) {
            owner->last = q;
            continue;
        }
        release_buffer(q);
    }
}

int ok_loop_free_then_return(int count) {
    for (int i = 0; i < count; i++) {
        char *p = malloc(8);
        if (p == PRODUCT_NULL) {
            continue;
        }
        consume(p);
        free(p);
    }
    return 0;
}

bool bacfile_object_name_set(uint32_t object_instance, const char *new_name) {
    bool status = 0;
    struct object_data *pObject;

    pObject = Keylist_Data(Object_List, object_instance);
    if (pObject) {
        status = 1;
        free(pObject->Object_Name);
        pObject->Object_Name = bacnet_strdup(new_name);
    }

    return status;
}
