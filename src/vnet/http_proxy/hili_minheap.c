#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>

#include <vppinfra/mem.h>
#include <vnet/http_proxy/hili_minheap.h>

static void swap_int(int* a, int* b) {
    int tmp = *a; 
    *a = *b; 
    *b = tmp;
}

static void selectsort(int array[],int startIndex,int endIndex){
  int i,j,minIndex;
  for(i=startIndex;i<endIndex;i++){
    minIndex=i;
    //选出�?小下标，放在�?前面
    for(j=i+1;j<=endIndex;j++){
      if(array[minIndex]>array[j]){
        minIndex=j;
      }   
    }   
    if(minIndex!=i){
      swap_int(&array[i],&array[minIndex]);
    }   
  }
}

/**
 * Note: The returned array must be malloced, assume caller calls free().
 */
/* 交换 */
static void swap(heap_entry_t **a, heap_entry_t **b) {
    heap_entry_t *tmp = *a;
    *a = *b; 
    *b = tmp;
}

/* 从堆下层向上交换元素，使得堆为大根堆 */
static void swim(heap_entry_t **nums, int k) {
    while (k > 1 && nums[k]->key < nums[k / 2]->key) {
        swap(&nums[k], &nums[k / 2]);
        k /= 2;
    }   
}

/* 从堆上层向下层交换元素，使得堆为大根�? */
static void sink(heap_entry_t **nums, int k, int numsSize) {
    while (2 * k < numsSize) {
        int child = 2 * k;
        if (child < numsSize && nums[child]->key > nums[child + 1]->key) {
            child++;
        }   
        if (nums[k]->key < nums[child]->key) {
            break;
        }   
        swap(&nums[k], &nums[child]);
        k = child;
    }
}

/* 初始化一个堆 */
PT_Heap createHeap(int k) {
	PT_Heap obj = (PT_Heap)clib_mem_alloc_aligned(sizeof(T_Heap), CLIB_CACHE_LINE_BYTES);
    obj->data = (heap_entry_t **)clib_mem_alloc_aligned(sizeof(heap_entry_t *) * (k + 1), CLIB_CACHE_LINE_BYTES);
    obj->szie = 0;
    obj->capacity = k + 1;
    return obj;
}

/* 判断堆是否为�? */
bool isEmpty(PT_Heap obj) {
    return obj->szie == 0;
}

/* 获得堆的当前大小 */
int getHeapSize(PT_Heap obj) {
    return obj->szie;
}

/* 将元素入�? */
void pushHeap(PT_Heap obj, heap_entry_t *elemp) {
    /* 新加入的元素放入堆的�?�? */
    obj->data[++obj->szie] = elemp;
    /* 对当前堆进行排序,使其成为�?个大根堆 */
    swim(obj->data, obj->szie);
}

/* 获得堆顶元素 */
heap_entry_t *getHeapTop(PT_Heap obj) {
    return obj->data[1];
}

/* 将堆顶元素出�? */
heap_entry_t *popHeap(PT_Heap obj) {
    /* 保存堆顶元素 */
    heap_entry_t *top = obj->data[1];
    /* 将堆顶元素和堆底元素交换,同时堆长度减�? */
    swap(&obj->data[1], &obj->data[obj->szie--]);
    /* 将原先的堆底元素赋�?�为INT_MIN */
    obj->data[obj->szie + 1] = NULL;
    /* 从堆顶开始重新堆�? */
    sink(obj->data, 1, obj->szie);
    return top;
}

static heap_entry_t **getLeastNumbers(heap_entry_t *arr, int arrSize, int k, int* returnSize){
    int i;
    heap_entry_t *hentry;
    /* 若数组为空�?�或k�?0，返回NULL */
    if (arrSize == 0 || k == 0) {
        *returnSize = 0;
        return NULL;
    } else {
        *returnSize = k;
    }
    /* 返回数组长度为k */
	heap_entry_t **ret = (heap_entry_t **)clib_mem_alloc_aligned(k * sizeof(heap_entry_t *), CLIB_CACHE_LINE_BYTES);
    /* 初始化一个大小为k的堆 */
    PT_Heap heap = createHeap(k);
    /* 将输入数组前k个元素堆�? */
    for (i = 0; i < k; i++) {
        pushHeap(heap, &arr[i]);
    }
    /* 将输入数组剩下的元素依次插入堆，得出�?小的k个数 */
    for (i = k; i < arrSize; i++) {
        hentry = getHeapTop(heap);
        if (arr[i].key > hentry->key) {
            popHeap(heap);
            pushHeap(heap, &arr[i]);
        }
    }
    /* 将堆中元素传入返回数�? */
    for (i = 0; i < k; i++) {
        ret[i] = popHeap(heap);
    }
    return ret;
}

static void print_origin_data(heap_entry_t **array, int size)
{
    int i;
    heap_entry_t *hentry;
    for (i = 0; i < size; i++) {
        hentry = array[i];
        printf("%lu ", hentry->key);
    }   
    printf("\n");
}

static void print_origin_data_2(heap_entry_t *array, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        printf("%lu ", array[i].key);
    }   
    printf("\n");
}

static void print_origin_data_int(int array[], int size)
{
    int i;
    for (i = 0; i < size; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
}


int hili_minheapt_init(void)
{
    int i;
    int ret_size;
    int int_array[15];
    struct heap_entry_s  hps[15];
    heap_entry_t **sorted_array;
    srand(time(NULL));
    for (i = 0; i < 15; i++) {
        int_array[i] = hps[i].key = rand()%100; 
    }   
    printf("origin_data:\n");
    print_origin_data_2(hps, 15);

    selectsort(int_array, 0, 14);
    printf("all sorted data:\n");
    print_origin_data_int(int_array, 15);

    sorted_array = getLeastNumbers(hps, 15, 8, &ret_size);
    printf("heap sorted data:\n");
    print_origin_data(sorted_array, ret_size);

    return 1;
}



