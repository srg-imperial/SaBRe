/*
 * RUN: %{cc} %s -o %t1
 * RUN: ! %{sbr} %t1
 */

int main() {
  return 1;
}
