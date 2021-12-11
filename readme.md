# 简介

so注入，自己研究用，详细请看 [Linux下进程隐藏 二 -- 进程注入（So注入）](https://9bie.org/index.php/archives/822/)


只支持x64，x86原理差不多，稍微改下shellcode和代码位数就行

编译方式

```
gcc main.c shellcode.s -no-pie -g -o inject -ldl
```
使用方式
```
./inject pid
```
远程进程必须要包含`dlfcn.h`，后续有心情了可能会更新