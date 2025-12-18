#ifndef OUTPUT_PRINTER_H
#define OUTPUT_PRINTER_H

enum valueType {
    INTEGER = 1,
    STRING = 2,
    UINT_8 = 3,
    UINT_16 = 4,
};

void print_protocol_header(char* protocol_name);
void print_field(char* name, void* value, enum valueType value_type);
void print_field2(char* name, void* value, enum valueType value_type);

#endif
