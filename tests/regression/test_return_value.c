/*
 * RUN: %{cc} %s -o %t1
 * RUN: ! %{vx} %t1
 */

int main() {
  return 1;
}
