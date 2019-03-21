/*
 * RUN: %{cc} %s -o %t2
 * RUN: $( $(%{vx} %t2 %t2 --); rc=$?; [[ $rc == 100 ]];)
 */


int main(int argc, char **argv) {
  return 100;
}
