/*
 * Copyright (C) 2021 caoguangwei279@163.com.
 * All Rights Reserved.
 */
#ifndef __HILI_MIN_HEAP_H__
#define __HILI_MIN_HEAP_H__

/*hed: heap entry data*/
typedef struct hed_4tuple_s
{
	uint32_t local_ip;
	uint32_t remote_ip;
	uint16_t local_port;
	uint16_t remote_port;
} hed_4tuple_t;

typedef struct hed_8tuple_s
{
	hed_4tuple_t req_info;
	hed_4tuple_t ups_info;
} hed_8tuple_t;

typedef struct heap_entry_s
{
	uint64_t key;
	char entry_data[0];
} heap_entry_t;

/* 定义堆的结构�? */
typedef struct Heap {
    heap_entry_t **data;
    int szie;
    int capacity;
}T_Heap, *PT_Heap;


/* 将元素入�? */
void pushHeap(PT_Heap obj, heap_entry_t *elem);

/* 获得堆顶元素 */
heap_entry_t *getHeapTop(PT_Heap obj);

/* 将堆顶元素出�? */
heap_entry_t *popHeap(PT_Heap obj);

PT_Heap createHeap(int k);
bool isEmpty(PT_Heap obj);
int getHeapSize(PT_Heap obj);

int hili_minheapt_init(void);

#endif /* __HILI_MIN_HEAP_H__ */

