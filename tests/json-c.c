#include <json-c/json.h>

int main() {
  json_object *jobj = json_tokener_parse(NULL);
  return 0;
}
