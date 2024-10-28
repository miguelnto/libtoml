#include "block.h"
#include <toml.h>
#include <string.h>
#include <stdlib.h>

/* We want the delimeter to be 3 characters long */
#define MAX_DELIM_LEN 3

/* Deinitializing the object, i.e freeing the memory. */
void config_deinit(Config *config) {
    for (unsigned int i = 0; i < config->blocks_len; i++) {
        if (config->blocks[i].command) {
            free(config->blocks[i].command);
        }
    }
    free(config->blocks);
    free(config);
}

/* Initiliazing the config object */
Config *config_init(void) {
    /* This is where we are going to store error messages. 
    * I don't really like this approach for error handling, but we will stick with it.
    * The API is definitely going to change any time soon, and we won't need to do this part. */
    char errbuf[200];

    /* Allocating memory for the config object */
    Config *config = calloc(1, sizeof(Config));
    if (!config) {
        fprintf(stderr, "Allocation failed: config\n");
        return NULL;
    }
    
    /* Parsing the toml file */
    toml_table *tbl = toml_parse_file("config.toml", errbuf, sizeof(errbuf));
    if (!tbl) {
        fprintf(stderr, "Error when parsing toml file: %s\n", errbuf);
        free(config);
        return NULL;
    }

    /* Get the delimiter which can't be bigger than 3 characters */
    toml_value delimeter = toml_table_string(tbl, "delimeter");
    if (!delimeter.ok) {
        fprintf(stderr, "Error when reading the value of delimeter\n");
        toml_table_free(tbl);
        return NULL;
    }
    /* Accessing the string */
    strncpy(config->delimeter, delimeter.value.String, MAX_DELIM_LEN);
    /* The string needs to be free'd */
    toml_string_free(delimeter.value.String);

    /* Get the array of tables "block" */
    toml_array *arr = toml_table_array(tbl, "block");
    if (!arr) {
        fprintf(stderr, "There's no array of tables <block>.\n");
        toml_table_free(tbl);
    }

    /* Get the length of the array */
    config->blocks_len = toml_array_len(arr);
    /* Allocating memory for the array of blocks */
    config->blocks = calloc(1, sizeof(Block)*config->blocks_len);
    if (!config->blocks) {
        fprintf(stderr, "Allocation failed: blocks\n");
        toml_table_free(tbl);
        return NULL;
    }

    /* We need this to store the current table through the iteration  */
    toml_table *ta = {0};
    /* We're going to read the value from the command, signal, and interval keys. */
    toml_value cmd = {0};
    toml_value interval = {0};
    toml_value sig = {0};

    for (unsigned int i = 0; i < config->blocks_len; i++) {
        ta = toml_array_table(arr, i);
        interval = toml_table_int(ta, "interval");
        /* Check if .ok. If not, cleanup everything and return NULL */
        if (!interval.ok) {
            fprintf(stderr, "Error when reading value from key <%s> at table of index <%d>\n", "interval" ,i);
            toml_table_free(tbl);
            config_deinit(config);
            return NULL;
        }
        sig = toml_table_int(ta, "signal");
        /* Check if .ok. If not, cleanup everything and return NULL */
        if (!sig.ok) {
            fprintf(stderr, "Error when reading value from key <%s> at table of index <%d>\n", "signal" ,i);
            toml_table_free(tbl);
            config_deinit(config);
            return NULL;
        }
        cmd = toml_table_string(ta, "command");
        /* Check if .ok. If not, cleanup everything and return NULL */
        if (!cmd.ok) {
            fprintf(stderr, "Error when reading value from key <%s> at table of index <%d>\n", "command" ,i);
            toml_table_free(tbl);
            config_deinit(config);
            return NULL;
        }
        const unsigned int cmdlen = strlen(cmd.value.String);
        /* Allocate memory for the command */
        config->blocks[i].command = calloc(1, cmdlen+1);
        if (!config->blocks[i].command) {
            fprintf(stderr, "Allocation failed: command\n");
            toml_table_free(tbl);
            config_deinit(config);
            return NULL;
        }
        /* Actually setting the values */
        strncpy(config->blocks[i].command, cmd.value.String, cmdlen);
        config->blocks[i].interval = interval.value.Integer;
        config->blocks[i].signal = sig.value.Integer;
        toml_string_free(cmd.value.String);
    }
    /* Let's free the table */
    toml_table_free(tbl);
    return config;
}

int main(void) {
    /* Init the config */
    Config *conf = config_init();
    if (conf) {
        printf("The command present in the last block is: %s\n", conf->blocks[2].command);
        /* Deinit the config */
        config_deinit(conf);
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
    /* Easy, huh? */
}
