#include "dnsinfo.h"
#include <pthread.h>
#include <stdio.h>

#ifdef ANDROID
#include <sys/system_properties.h>
#endif

static dns_config_t configuration;
static pthread_mutex_t configuration_lock = PTHREAD_MUTEX_INITIALIZER;
static void dns_resolver_free(dns_resolver_t *resolver);
static void dns_configuration_init(void) __attribute__((constructor));

static void dns_configuration_init(void) {
    configuration.n_resolver = 1;
    dns_resolver_t *resolver = malloc(sizeof(dns_resolver_t *));
#ifdef ANDROID
    resolver->nameserver = malloc(sizeof(struct sockaddr *) * 5); // reserve atleast 5 nameservers
    int ns_idx = 0;
    // nameservers can range from 1-5 (observed, however there may be more/less, but this should work for the 99.99% use case)
    for (int idx = 1; idx < 5; idx++) {
        char name[PROP_NAME_MAX];
        char value[PROP_VALUE_MAX];
        snprintf(name, PROP_NAME_MAX, "net.dns%d", idx);
        int res = __system_property_get(name, value); 
        DEBUG_LOG("%d", res);
        if (strlen(value) > 0) {
            struct sockaddr_in addr4;
            struct sockaddr_in6 addr6;
            // NOTE: this is probably inappropraite to use inet_pton here but meh whatcha goina do...?
            if (inet_pton(AF_INET, value, &(addr4.sin_addr)) == 1)
            {
                resolver->nameserver[ns_idx] = malloc(sizeof(struct sockaddr_in));
                if (resolver->nameserver[ns_idx] != NULL) {
                    memcpy(resolver->nameserver[ns_idx], &addr4, sizeof(struct sockaddr_in));
                    ns_idx++;
                    continue;
                }
            }
            if (inet_pton(AF_INET6, value, &(addr6.sin6_addr)) == 1)
            {
                resolver->nameserver[ns_idx] = malloc(sizeof(struct sockaddr_in6));
                if (resolver->nameserver[ns_idx] != NULL) {
                    memcpy(resolver->nameserver[ns_idx], &addr6, sizeof(struct sockaddr_in6));
                    ns_idx++;
                    continue;
                }
            }
            DEBUG_LOG("failure to convert address");
        }
    }
    configuration.resolver = &resolver;
#endif
}

const char *dns_configuration_notify_key(void) {
    return "dns.config.notify";
}

static dns_resolver_t *dns_resolver_copy(dns_resolver_t *resolver) {
    dns_resolver_t *copy = NULL;
    int success = 0;
    int failure = 0;
    do {
        copy = malloc(sizeof(dns_resolver_t));
        if (copy == NULL) {
            break;
        }
        if (resolver->domain != NULL) {
            copy->domain = strdup(resolver->domain);
            if (copy->domain == NULL) {
                break;
            }
        }

        copy->n_nameserver = resolver->n_nameserver;
        if (copy->n_nameserver > 0) {
            copy->nameserver = malloc(sizeof(dns_resolver_t *));
            if (copy->nameserver == NULL) {
                break;
            }
            for (int i = 0; i < copy->n_nameserver; i++) {
                size_t len = 0;
                if (resolver->nameserver[i]->sa_family == AF_INET) {
                    len = sizeof(struct sockaddr_in);
                } else if (resolver->nameserver[i]->sa_family == AF_INET6) {
                    len = sizeof(struct sockaddr_in6);
                } else {
                    failure = 1;
                    break;
                }
                copy->nameserver[i] = malloc(len);
                if (copy->nameserver[i] == NULL) {
                    failure = 1;
                    break;
                }
                memcpy(copy->nameserver[i], resolver->nameserver[i], len);
            }
            if (failure) {
                break;
            }
        } else {
            copy->nameserver = NULL;
        }

        copy->port = resolver->port;

        copy->n_search = resolver->n_search;
        if (copy->n_search > 0) {
            copy->search = malloc(sizeof(char *));
            if (copy->search == NULL) {
                break;
            }
            for (int i = 0; i < copy->n_search; i++) {
                if (resolver->search[i] != NULL) {
                    copy->search[i] = strdup(resolver->search[i]);
                    if (copy->search[i] == NULL) {
                        failure = 1;
                        break; 
                    }
                } else {
                    copy->search[i] = NULL;
                }
            }
            if (failure) {
                break;
            }
        } else {
            copy->search = NULL;
        }

        copy->n_sortaddr = resolver->n_sortaddr;
        if (copy->n_sortaddr > 0) {
            copy->sortaddr = malloc(sizeof(dns_sortaddr_t *));
            if (copy->sortaddr == NULL) {
                break;
            }
            for (int i = 0; i < copy->n_sortaddr; i++) {
                if (resolver->sortaddr[i] != NULL) {
                    copy->sortaddr[i] = malloc(sizeof(dns_sortaddr_t));
                    if (copy->sortaddr[i] == NULL) {
                        failure = 1;
                        break;
                    }
                    memcpy(copy->sortaddr[i], resolver->sortaddr[i], sizeof(dns_sortaddr_t));
                } else {
                    copy->search[i] = NULL;
                }
            }
            if (failure) {
                break;
            }
        } else {
            copy->search = NULL;
        }

        if (resolver->options != NULL) {
            copy->options = strdup(resolver->options);
            if (copy->options == NULL) {
                break;
            }
        } else {
            copy->options = NULL;
        }

        copy->timeout = resolver->timeout;
        copy->search_order = resolver->search_order;
        
        success = 1;
    } while (0);
    if (!success) {
        dns_resolver_free(copy);
        copy = NULL;
    }
    return copy;
}

dns_config_t *dns_configuration_copy(void) {
    dns_config_t *config = NULL;
    int success = 0;
    int failure = 0;
    pthread_mutex_lock(&configuration_lock);
    do {
        config = malloc(sizeof(dns_config_t));
        if (config == NULL) {
            break;
        }
        config->n_resolver = configuration.n_resolver;
        if (config->n_resolver > 0) {
            config->resolver = malloc(sizeof(dns_resolver_t *));
            if (config->resolver == NULL) {
                break;
            }
            for (int i = 0; i < config->n_resolver; i++) {
                config->resolver[i] = dns_resolver_copy(configuration.resolver[i]);
                if (config->resolver[i] == NULL) {
                    failure = 1;
                    break;
                }
            }
            if (failure) {
                break;
            }
        } else {
            config->resolver = NULL;
        }
        
        success = 1;
    } while (0);
    pthread_mutex_unlock(&configuration_lock);
    if (!success || failure) {
        dns_configuration_free(config);
        config = NULL;
    }
    return config;
}

#define DNS_FREE_PTR(item, name, method) do { \
    if (item->name != NULL) { \
        method(item->name); \
        item->name = NULL; \
    } \
} while (0)

#define DNS_FREE_LIST(item, name, method) do { \
    if (item->name != NULL) { \
        for (int i = 0; i < item->n ## _ ## name; i++) { \
            method(item->name[i]); \
        } \
        free(item->name); \
        item->name = NULL; \
    } \
} while (0)

static void dns_resolver_free(dns_resolver_t *resolver) {
    if (resolver != NULL) {
        DNS_FREE_PTR(resolver, domain, free);
        DNS_FREE_LIST(resolver, nameserver, free);
        DNS_FREE_LIST(resolver, search, free);
        DNS_FREE_LIST(resolver, sortaddr, free);
        DNS_FREE_PTR(resolver, options, free);
        // this is taken care of by the free list macro...
        // free(resolver)
    }
}

void dns_configuration_free(dns_config_t *config) {
    if (config != NULL) {
        DNS_FREE_LIST(config, resolver, dns_resolver_free);
        free(config);
    }
}