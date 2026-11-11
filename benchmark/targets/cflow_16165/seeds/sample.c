int bar(int x) {
    return x * 2;
}

int foo(int y) {
    return bar(y) + 1;
}

int main(void) {
    return foo(5);
}

