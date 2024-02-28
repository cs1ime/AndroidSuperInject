#ifndef _TOUCHLAB_STRUCTS_H_
#define _TOUCHLAB_STRUCTS_H_

#include <stdbool.h>
#include <linux/uinput.h>
#include <android/input.h>
#include <android/keycodes.h>

enum TouchEventType
{
    TOUCH_DOWN = 0,
    TOUCH_MOVE,
    TOUCH_UP,
};

struct TouchEvent
{
    int type;
    int64_t timestamp;
    int fingerIndex;
    float posX;
    float posY;
};
struct input_event_block
{
    struct input_event event;
};

struct universal_events_queue {
    #define UNIVERSAL_EVENTS_QUEUE_SIZE (200)
    int from,rear;
    struct input_event_block data[UNIVERSAL_EVENTS_QUEUE_SIZE];
    
};
void universal_events_queue_initialize(struct universal_events_queue *q)
{
    q->from=0;
    q->rear=0;
}
bool universal_events_queue_inqueue(struct universal_events_queue *q,const struct input_event_block* event)
{
    int nextrear = (q->rear + 1) % UNIVERSAL_EVENTS_QUEUE_SIZE;
    if(nextrear == q->from){
        return false;
    }
    q->data[q->rear]=*event;
    q->rear=nextrear;
    return true;
}
bool universal_events_queue_dequeue(struct universal_events_queue *q,struct input_event_block* outEvent){
    if(q->from == q->rear)
        return false;
    *outEvent=q->data[q->from];
    q->from=(q->from+1) % UNIVERSAL_EVENTS_QUEUE_SIZE;
    return true;
}
int universal_events_queue_length(const struct universal_events_queue *q)
{
    if (q->rear >= q->from) {
        return q->rear - q->from;
    } else {
        return UNIVERSAL_EVENTS_QUEUE_SIZE - (q->from - q->rear);
    }
}

#endif

