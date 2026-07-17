---
name: resleak
description: 验证各类资源泄露候选漏洞（文件/套接字/锁/内存/映射/数据库/线程等）
---

# 全类型资源泄露漏洞验证

你正在核实一处候选资源泄露线索。你的任务是判断这是真实的 bug 还是误报。

## 背景

候选线索来自这样一种形态：函数中存在资源释放调用，并且在某个退出点（return/goto/continue）之前，资源在**其他路径**上被释放，但在**当前路径**上未被释放。候选描述中包含了疑似泄露的变量名以及其他路径的释放行号。

## 资源类型与释放函数对照表

| 资源类型 | 典型获取函数 | 正确释放方式 |
|---------|------------|------------|
| 堆内存 | malloc/calloc/realloc/strdup/new | free() / delete / delete[] |
| FILE 句柄 | fopen/fdopen/freopen | fclose() |
| 文件描述符 | open/creat/dup/dup2 | close() |
| 套接字 | socket/accept/socketpair | close() / closesocket() |
| 互斥锁持有 | pthread_mutex_lock/trylock | pthread_mutex_unlock() |
| 读写锁持有 | pthread_rwlock_rdlock/wrlock/tryr/tryw | pthread_rwlock_unlock() |
| 信号量占用 | sem_wait/sem_timedwait/sem_trywait | sem_post() |
| 动态库句柄 | dlopen | dlclose() |
| 内存映射 | mmap | munmap() |
| SQLite 数据库 | sqlite3_open/open_v2 | sqlite3_close() |
| SQLite 语句 | sqlite3_prepare/prepare_v2 | sqlite3_finalize() |
| POSIX 消息队列 | mq_open | mq_close() |
| POSIX 定时器 | timer_create | timer_delete() |
| 线程句柄 | pthread_create | pthread_join() 或 pthread_detach() |
| 共享内存 | shm_open | close() + shm_unlink() |
| 自定义资源 | *alloc/*create/*init/*open/*get | 对应的 *free/*destroy/*close/*release/*put |

## 分析步骤

```
第 1 步  阅读完整函数源码
第 2 步  定位候选描述中的资源获取点，确认变量类型和获取方式
第 3 步  追踪每个退出路径（return / goto / continue）上的释放行为
第 4 步  检查自定义释放函数的语义
第 5 步  判断是否存在所有权转移或其他释放机制
第 6 步  汇总并形成结论
```

## 判定标准

### 判为误报 (confirmed=false) 的情形

1. **空值/失败检测退出**：退出点之前有对资源的判空检测（`if (!fp) return;`），此时资源本就未成功获取
2. **资源未在当前路径获取**：函数前段的参数校验 return，此时分配尚未发生
3. **所有权转移给调用者**：资源作为函数返回值、通过指针参数输出，或赋值到 `*out_param`，由调用方负责释放
4. **所有权转移给数据结构**：资源存入结构体字段、链表节点、全局/静态变量，转交其他模块管理
5. **消息/回调转移**：通过 SendMsg/PostMsg/Enqueue/Dispatch/回调等机制移交给框架
6. **封装释放**：自定义 cleanup/destroy/fini/free_xxx 函数内部已包含对该资源的释放
7. **RAII 保护**：std::unique_ptr/shared_ptr、std::lock_guard/unique_lock、scope_exit 等确保释放
8. **goto cleanup 模式**：函数用 `goto cleanup` 跳转到统一释放标签处，所有退出均会经过
9. **锁的条件性获取**：mutex_lock 在 if 分支内，只有进入该分支才持有锁，early-return 时锁并未被持有
10. **非真实资源**：变量是栈上纯值或表示"无资源"的初始值（fd=-1, fp=NULL）
11. **测试/桩代码**：文件路径含 test/stub/mock/dt/fake/dummy

### 判为真实漏洞 (confirmed=true) 的条件

- 资源在当前退出路径上确实已成功获取
- 退出前没有调用对应释放函数，也没有通过其他方式转移所有权
- 函数其他路径存在明确的释放操作可对比
- 泄露会在实际运行中重复触发（非一次性或可忽略）

## 结论内容

分析完成后按以下字段给出结论：

| 参数 | 规则 |
|------|------|
| `confirmed` | true = 确认漏洞；false = 误报 |
| `severity` | high：文件描述符/套接字/锁持有必定泄露；medium：内存或条件性泄露；low：边缘情况 |
| `description` | 一句话摘要，注明资源类型和函数名，例："函数 process_conn 的错误路径未关闭套接字 sock_fd" |
| `ai_analysis` | 详细推理：资源获取位置→泄露路径描述→排除/确认理由 |
