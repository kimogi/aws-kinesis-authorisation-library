#include <stdlib.h>
#include <string.h>

typedef struct list_item {
	char *data;
	int data_len;
	struct list_item *next;
} Listitem;

typedef struct list {
	Listitem *head;
	int size;
} List;

int add_new_item_with_data(List *list, char *data, int data_len);
int add_item(List *list, Listitem *item);
char *join_all_lines(List *lines, char *divider);
int get_total_length_bytes(List *lines);
void free_list(List *list);
int listcat(List *dest, List *src);
