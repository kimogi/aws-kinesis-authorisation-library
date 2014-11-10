#include "list.h"

int add_new_item_with_data(List *list, char *data, int data_len) {
        if(NULL == list || NULL == data || 0 > data_len) {
                puts("Failed to add new item with data");
		return -1;
	}

        Listitem *item = (Listitem *)calloc(1, sizeof(Listitem));
        item->data = (char *)calloc(data_len + 1, sizeof(char));
	item->data_len = data_len;
	memcpy(item->data, data, data_len);
        return add_item(list, item);
}

int add_item(List *list, Listitem *item) {
        if(NULL == list || NULL == item) {
                puts("Failed to add new item");
		return -1;
	}
        
	if(NULL == list->head) {
		list->head = item;
	} else {
		Listitem *knot = list->head;
        	while(NULL != knot->next)
                	knot = knot->next;
        	knot->next = item;
	}
        return ++(list->size);
}

int listcat(List *dest, List *src) {
	if(NULL == dest || NULL == src) {
                puts("Failed to cat lists");
                return -1;
        }
	
	Listitem *src_knot = src->head;
	while(NULL != src_knot) {
		add_new_item_with_data(dest, src_knot->data, src_knot->data_len);
		src_knot = src_knot->next;
	}
	return dest->size;
}

char *join_all_lines(List *lines, char *divider) {
        if(NULL == lines)
                return NULL;
	
	int total_length_bytes = get_total_length_bytes(lines);
	if(-1 == total_length_bytes)
		return NULL;	

	char *result_line = (char *)calloc(total_length_bytes + lines->size + 1, sizeof(char));

	Listitem *line = lines->head;
	while(NULL != line) {
               	strcat(result_line, line->data);
		if(NULL != line->next) {
			strcat(result_line, divider);
		}
		line = line->next;
        }
	return result_line;
}

int get_total_length_bytes(List *lines) {
	if(NULL == lines) {
		puts("Falied to count total lenght of list");
		return -1;
	}

	int total_length_bytes = 0;
	Listitem *line = lines->head;
	while(NULL != line) {
		total_length_bytes += line->data_len;
		line = line->next;
	}
	return total_length_bytes;
}

void free_list(List *list) {
	if(NULL == list)
		return;
	
	Listitem *head = list->head;
	Listitem *temp = NULL;
        while(NULL != head) {
		temp = head;
                head = head->next;
		free(temp);
        }
	free(list);
}
