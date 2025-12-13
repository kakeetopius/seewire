#ifndef OUTPUT_PRINTER_H
#define OUTPUT_PRINTER_H

enum valueType {
    INTEGER = 1,
    STRING = 2
};

void print_protocol_header(char* protocol_name);
void print_field(char* name, void* value, enum valueType value_type);

#endif
