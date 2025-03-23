#ifndef LIST_H
#define LIST_H

enum valueType {
    INTEGER,
    FLOAT,
    CHARACTER,
    STRING
};

typedef struct list {
    /*======Attributes============*/
    int listSize;
    struct node* firstNode;
    struct node* lastNode;
    struct list* self;
    void* value; // pointer to the value requested to return.
    /*==========Methods================*/
    int (*destroyList)(struct list* list);
    int (*append)(struct list* list, char* data, enum valueType);
    int (*insertAt)(struct list* list, char* data, int position, enum valueType);
    int (*getAt)(struct list* list, int position);
    int (*isEmpty)(struct list* list);
    int (*removeItem)(struct list* list, char* data, enum valueType);
    int (*removeAt)(struct list* list, int position);
    void (*printList)(struct list* list);
    void (*clear)(struct list* list);
    int (*size)(struct list* list);
}list, *List;


/*Returns a list object (struct list pointer)*/
List createList();


/*appends item  in string literal data to the list as datatype type*/
/*Returns 0 on success and -1 on failure*/
int listAppend(List lst, char* data, enum valueType type);


/*inserts item in string literal data to the list at position indicated as datatype type*/
/*Returns 0 on success and -1 on failure*/
int listInsertAt(List lst, char* data, int position, enum valueType type);


/*Returns the type of item (STRING, CHARACTER, INTEGER OR FLOAT)* and -1 on failure*/
/*Every call to this function updates the value element of the list struct with 
a pointer to the value at the position given.*/
int listGetAt(List lst, int position);


/*removes the item in string literal data and with data type type*/
/*Returns 0 on success and -1 if item is not found*/
int listRemoveItem(List lst, char* data, enum valueType type);


/*removes the item at position given*/
/*Return 0 on success and -1 on failure*/
int listRemoveAt(List lst, int position);

/*Print to standard output the items in the list*/
void printList(List lst);


/*Clear all the items in the list*/
void clearList(List lst);


/*Returns the size of the list*/
int sizeofList(List lst);


/*Cleans memory allocated for the List and all its elements. 
Should always be called after using the list
List can't be used after being called*/
int destroyList(List lst);


/*Checks if the list is empty
Returns 0 if empty and 1 otherwise*/
int isEmpty(List lst);

#endif
