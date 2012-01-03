/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Portions Copyright 2011 Joyent, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "sysemu.h"
#include "net.h"
#include "monitor.h"
#include "console.h"
#include "trace.h"

#include "hw/hw.h"

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#endif

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/rtc.h>
/* For the benefit of older linux systems which don't supply it,
   we use a local copy of hpet.h. */
/* #include <linux/hpet.h> */
#include "hpet.h"
#endif

#ifdef _WIN32
#include <windows.h>
#include <mmsystem.h>
#endif

#include "qemu-timer.h"

/* Conversion factor from emulated instructions to virtual clock ticks.  */
int icount_time_shift;
/* Arbitrarily pick 1MIPS as the minimum allowable speed.  */
#define MAX_ICOUNT_SHIFT 10
/* Compensate for varying guest execution speed.  */
int64_t qemu_icount_bias;
static QEMUTimer *icount_rt_timer;
static QEMUTimer *icount_vm_timer;

/***********************************************************/
/* guest cycle counter */

typedef struct TimersState {
    int64_t cpu_ticks_prev;
    int64_t cpu_ticks_offset;
    int64_t cpu_clock_offset;
    int32_t cpu_ticks_enabled;
    int64_t dummy;
} TimersState;

TimersState timers_state;

/* return the host CPU cycle counter and handle stop/restart */
int64_t cpu_get_ticks(void)
{
    if (use_icount) {
        return cpu_get_icount();
    }
    if (!timers_state.cpu_ticks_enabled) {
        return timers_state.cpu_ticks_offset;
    } else {
        int64_t ticks;
        ticks = cpu_get_real_ticks();
        if (timers_state.cpu_ticks_prev > ticks) {
            /* Note: non increasing ticks may happen if the host uses
               software suspend */
            timers_state.cpu_ticks_offset += timers_state.cpu_ticks_prev - ticks;
        }
        timers_state.cpu_ticks_prev = ticks;
        return ticks + timers_state.cpu_ticks_offset;
    }
}

/* return the host CPU monotonic timer and handle stop/restart */
static int64_t cpu_get_clock(void)
{
    int64_t ti;
    if (!timers_state.cpu_ticks_enabled) {
        return timers_state.cpu_clock_offset;
    } else {
        ti = get_clock();
        return ti + timers_state.cpu_clock_offset;
    }
}

static int64_t qemu_icount_delta(void)
{
    if (!use_icount) {
        return 5000 * (int64_t) 1000000;
    } else if (use_icount == 1) {
        /* When not using an adaptive execution frequency
           we tend to get badly out of sync with real time,
           so just delay for a reasonable amount of time.  */
        return 0;
    } else {
        return cpu_get_icount() - cpu_get_clock();
    }
}

/* enable cpu_get_ticks() */
void cpu_enable_ticks(void)
{
    if (!timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset -= cpu_get_real_ticks();
        timers_state.cpu_clock_offset -= get_clock();
        timers_state.cpu_ticks_enabled = 1;
    }
}

/* disable cpu_get_ticks() : the clock is stopped. You must not call
   cpu_get_ticks() after that.  */
void cpu_disable_ticks(void)
{
    if (timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset = cpu_get_ticks();
        timers_state.cpu_clock_offset = cpu_get_clock();
        timers_state.cpu_ticks_enabled = 0;
    }
}

/***********************************************************/
/* timers */

#define QEMU_CLOCK_REALTIME 0
#define QEMU_CLOCK_VIRTUAL  1
#define QEMU_CLOCK_HOST     2

struct QEMUClock {
    int type;
    int enabled;
    /* XXX: add frequency */
};

struct QEMUTimer {
    QEMUClock *clock;
    int64_t expire_time;
    int64_t interval;
    QEMUTimerCB *cb;
    void *opaque;
    void *source;
    struct QEMUTimer *next;
};

struct qemu_alarm_timer {
    char const *name;
    int (*start)(struct qemu_alarm_timer *t);
    void (*stop)(struct qemu_alarm_timer *t);
    void (*rearm)(struct qemu_alarm_timer *t);
    void *priv;

    char expired;
    char pending;
};

static struct qemu_alarm_timer *alarm_timer;

int qemu_alarm_pending(void)
{
    return alarm_timer->pending;
}

static inline int alarm_has_dynticks(struct qemu_alarm_timer *t)
{
    return !!t->rearm;
}

static void qemu_rearm_alarm_timer(struct qemu_alarm_timer *t)
{
    if (!alarm_has_dynticks(t))
        return;

    t->rearm(t);
}

/* TODO: MIN_TIMER_REARM_NS should be optimized */
#define MIN_TIMER_REARM_NS 250000

#ifdef _WIN32

struct qemu_alarm_win32 {
    MMRESULT timerId;
    unsigned int period;
} alarm_win32_data = {0, 0};

static int win32_start_timer(struct qemu_alarm_timer *t);
static void win32_stop_timer(struct qemu_alarm_timer *t);
static void win32_rearm_timer(struct qemu_alarm_timer *t);

#else

static int unix_start_timer(struct qemu_alarm_timer *t);
static void unix_stop_timer(struct qemu_alarm_timer *t);

#if defined(__sun__)

static int multiticks_start_timer(struct qemu_alarm_timer *t);
static void multiticks_stop_timer(struct qemu_alarm_timer *t);
static void multiticks_rearm_timer(struct qemu_alarm_timer *t);

#endif

#if defined(__linux__) || defined(__sun__)

static int dynticks_start_timer(struct qemu_alarm_timer *t);
static void dynticks_stop_timer(struct qemu_alarm_timer *t);
static void dynticks_rearm_timer(struct qemu_alarm_timer *t);

#endif

#ifdef __linux__

static int hpet_start_timer(struct qemu_alarm_timer *t);
static void hpet_stop_timer(struct qemu_alarm_timer *t);

static int rtc_start_timer(struct qemu_alarm_timer *t);
static void rtc_stop_timer(struct qemu_alarm_timer *t);

#endif /* __linux__ */

#endif /* _WIN32 */

/* Correlation between real and virtual time is always going to be
   fairly approximate, so ignore small variation.
   When the guest is idle real and virtual time will be aligned in
   the IO wait loop.  */
#define ICOUNT_WOBBLE (get_ticks_per_sec() / 10)

static void icount_adjust(void)
{
    int64_t cur_time;
    int64_t cur_icount;
    int64_t delta;
    static int64_t last_delta;
    /* If the VM is not running, then do nothing.  */
    if (!vm_running)
        return;

    cur_time = cpu_get_clock();
    cur_icount = qemu_get_clock(vm_clock);
    delta = cur_icount - cur_time;
    /* FIXME: This is a very crude algorithm, somewhat prone to oscillation.  */
    if (delta > 0
        && last_delta + ICOUNT_WOBBLE < delta * 2
        && icount_time_shift > 0) {
        /* The guest is getting too far ahead.  Slow time down.  */
        icount_time_shift--;
    }
    if (delta < 0
        && last_delta - ICOUNT_WOBBLE > delta * 2
        && icount_time_shift < MAX_ICOUNT_SHIFT) {
        /* The guest is getting too far behind.  Speed time up.  */
        icount_time_shift++;
    }
    last_delta = delta;
    qemu_icount_bias = cur_icount - (qemu_icount << icount_time_shift);
}

static void icount_adjust_rt(void * opaque)
{
    qemu_mod_timer(icount_rt_timer,
                   qemu_get_clock(rt_clock) + 1000);
    icount_adjust();
}

static void icount_adjust_vm(void * opaque)
{
    qemu_mod_timer(icount_vm_timer,
                   qemu_get_clock(vm_clock) + get_ticks_per_sec() / 10);
    icount_adjust();
}

int64_t qemu_icount_round(int64_t count)
{
    return (count + (1 << icount_time_shift) - 1) >> icount_time_shift;
}

static struct qemu_alarm_timer alarm_timers[] = {
#ifndef _WIN32
#if defined(__sun__)
    {"multiticks", multiticks_start_timer,
     multiticks_stop_timer, multiticks_rearm_timer, NULL},
#endif
#if defined(__linux__) || defined(__sun__)
    {"dynticks", dynticks_start_timer,
     dynticks_stop_timer, dynticks_rearm_timer, NULL},
#endif
#ifdef __linux__
    /* HPET - if available - is preferred */
    {"hpet", hpet_start_timer, hpet_stop_timer, NULL, NULL},
    /* ...otherwise try RTC */
    {"rtc", rtc_start_timer, rtc_stop_timer, NULL, NULL},
#endif
    {"unix", unix_start_timer, unix_stop_timer, NULL, NULL},
#else
    {"dynticks", win32_start_timer,
     win32_stop_timer, win32_rearm_timer, &alarm_win32_data},
    {"win32", win32_start_timer,
     win32_stop_timer, NULL, &alarm_win32_data},
#endif
    {NULL, }
};

static void show_available_alarms(void)
{
    int i;

    printf("Available alarm timers, in order of precedence:\n");
    for (i = 0; alarm_timers[i].name; i++)
        printf("%s\n", alarm_timers[i].name);
}

void configure_alarms(char const *opt)
{
    int i;
    int cur = 0;
    int count = ARRAY_SIZE(alarm_timers) - 1;
    char *arg;
    char *name;
    struct qemu_alarm_timer tmp;

    if (!strcmp(opt, "?")) {
        show_available_alarms();
        exit(0);
    }

    arg = qemu_strdup(opt);

    /* Reorder the array */
    name = strtok(arg, ",");
    while (name) {
        for (i = 0; i < count && alarm_timers[i].name; i++) {
            if (!strcmp(alarm_timers[i].name, name))
                break;
        }

        if (i == count) {
            fprintf(stderr, "Unknown clock %s\n", name);
            goto next;
        }

        if (i < cur)
            /* Ignore */
            goto next;

	/* Swap */
        tmp = alarm_timers[i];
        alarm_timers[i] = alarm_timers[cur];
        alarm_timers[cur] = tmp;

        cur++;
next:
        name = strtok(NULL, ",");
    }

    qemu_free(arg);

    if (cur) {
        /* Disable remaining timers */
        for (i = cur; i < count; i++)
            alarm_timers[i].name = NULL;
    } else {
        show_available_alarms();
        exit(1);
    }
}

#define QEMU_NUM_CLOCKS 3

QEMUClock *rt_clock;
QEMUClock *vm_clock;
QEMUClock *host_clock;

static QEMUTimer *active_timers[QEMU_NUM_CLOCKS];

static QEMUClock *qemu_new_clock(int type)
{
    QEMUClock *clock;
    clock = qemu_mallocz(sizeof(QEMUClock));
    clock->type = type;
    clock->enabled = 1;
    return clock;
}

void qemu_clock_enable(QEMUClock *clock, int enabled)
{
    clock->enabled = enabled;
}

QEMUTimer *qemu_new_timer(QEMUClock *clock, QEMUTimerCB *cb, void *opaque)
{
    QEMUTimer *ts;

    ts = qemu_mallocz(sizeof(QEMUTimer));
    ts->clock = clock;
    ts->cb = cb;
    ts->opaque = opaque;
    return ts;
}

void qemu_free_timer(QEMUTimer *ts)
{
    qemu_free(ts);
}

/* stop a timer, but do not dealloc it */
void qemu_del_timer(QEMUTimer *ts)
{
    QEMUTimer **pt, *t;

    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */
    pt = &active_timers[ts->clock->type];
    for(;;) {
        t = *pt;
        if (!t)
            break;
        if (t == ts) {
            *pt = t->next;
            break;
        }
        pt = &t->next;
    }
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time. The corresponding callback will be called. */
void qemu_mod_timer(QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimer **pt, *t;

    qemu_del_timer(ts);

    /* add the timer in the sorted list */
    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */
    pt = &active_timers[ts->clock->type];
    for(;;) {
        t = *pt;
        if (!t)
            break;
        if (t->expire_time > expire_time)
            break;
        pt = &t->next;
    }

    if (ts->expire_time && expire_time > ts->expire_time) {
        ts->interval = expire_time - ts->expire_time;
    } else {
        ts->interval = 0;
    }

    ts->expire_time = expire_time;
    ts->next = *pt;
    *pt = ts;

    trace_qemu_mod_timer(ts, expire_time, ts->interval);

    /* Rearm if necessary  */
    if (pt == &active_timers[ts->clock->type]) {
        if (!alarm_timer->pending) {
            qemu_rearm_alarm_timer(alarm_timer);
        }
        /* Interrupt execution to force deadline recalculation.  */
        if (use_icount)
            qemu_notify_event();
    }
}

int qemu_timer_pending(QEMUTimer *ts)
{
    QEMUTimer *t;
    for(t = active_timers[ts->clock->type]; t != NULL; t = t->next) {
        if (t == ts)
            return 1;
    }
    return 0;
}

int qemu_timer_expired(QEMUTimer *timer_head, int64_t current_time)
{
    if (!timer_head)
        return 0;
    return (timer_head->expire_time <= current_time);
}

static void qemu_run_timers(QEMUClock *clock)
{
    QEMUTimer **ptimer_head, *ts;
    int64_t current_time;
   
    if (!clock->enabled)
        return;

    current_time = qemu_get_clock (clock);
    ptimer_head = &active_timers[clock->type];
    for(;;) {
        ts = *ptimer_head;
        if (!ts || ts->expire_time > current_time)
            break;

        trace_qemu_run_timer(ts, ts->expire_time, current_time);

        /* remove timer from the list before calling the callback */
        *ptimer_head = ts->next;
        ts->next = NULL;

        /* run the callback (the timer list can be modified) */
        ts->cb(ts->opaque);
    }
}

int64_t qemu_get_clock(QEMUClock *clock)
{
    switch(clock->type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock() / 1000000;
    default:
    case QEMU_CLOCK_VIRTUAL:
        if (use_icount) {
            return cpu_get_icount();
        } else {
            return cpu_get_clock();
        }
    case QEMU_CLOCK_HOST:
        return get_clock_realtime();
    }
}

int64_t qemu_get_clock_ns(QEMUClock *clock)
{
    switch(clock->type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock();
    default:
    case QEMU_CLOCK_VIRTUAL:
        if (use_icount) {
            return cpu_get_icount();
        } else {
            return cpu_get_clock();
        }
    case QEMU_CLOCK_HOST:
        return get_clock_realtime();
    }
}

void init_clocks(void)
{
    rt_clock = qemu_new_clock(QEMU_CLOCK_REALTIME);
    vm_clock = qemu_new_clock(QEMU_CLOCK_VIRTUAL);
    host_clock = qemu_new_clock(QEMU_CLOCK_HOST);

    rtc_clock = host_clock;
}

/* save a timer */
void qemu_put_timer(QEMUFile *f, QEMUTimer *ts)
{
    uint64_t expire_time;

    if (qemu_timer_pending(ts)) {
        expire_time = ts->expire_time;
    } else {
        expire_time = -1;
    }
    qemu_put_be64(f, expire_time);
}

void qemu_get_timer(QEMUFile *f, QEMUTimer *ts)
{
    uint64_t expire_time;

    expire_time = qemu_get_be64(f);
    if (expire_time != -1) {
        qemu_mod_timer(ts, expire_time);
    } else {
        qemu_del_timer(ts);
    }
}

static const VMStateDescription vmstate_timers = {
    .name = "timer",
    .version_id = 2,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields      = (VMStateField []) {
        VMSTATE_INT64(cpu_ticks_offset, TimersState),
        VMSTATE_INT64(dummy, TimersState),
        VMSTATE_INT64_V(cpu_clock_offset, TimersState, 2),
        VMSTATE_END_OF_LIST()
    }
};

void configure_icount(const char *option)
{
    vmstate_register(NULL, 0, &vmstate_timers, &timers_state);
    if (!option)
        return;

    if (strcmp(option, "auto") != 0) {
        icount_time_shift = strtol(option, NULL, 0);
        use_icount = 1;
        return;
    }

    use_icount = 2;

    /* 125MIPS seems a reasonable initial guess at the guest speed.
       It will be corrected fairly quickly anyway.  */
    icount_time_shift = 3;

    /* Have both realtime and virtual time triggers for speed adjustment.
       The realtime trigger catches emulated time passing too slowly,
       the virtual time trigger catches emulated time passing too fast.
       Realtime triggers occur even when idle, so use them less frequently
       than VM triggers.  */
    icount_rt_timer = qemu_new_timer(rt_clock, icount_adjust_rt, NULL);
    qemu_mod_timer(icount_rt_timer,
                   qemu_get_clock(rt_clock) + 1000);
    icount_vm_timer = qemu_new_timer(vm_clock, icount_adjust_vm, NULL);
    qemu_mod_timer(icount_vm_timer,
                   qemu_get_clock(vm_clock) + get_ticks_per_sec() / 10);
}

void qemu_run_all_timers(void)
{
    alarm_timer->pending = 0;

    /* rearm timer, if not periodic */
    if (alarm_timer->expired) {
        alarm_timer->expired = 0;
        qemu_rearm_alarm_timer(alarm_timer);
    }

    /* vm time timers */
    if (vm_running) {
        qemu_run_timers(vm_clock);
    }

    qemu_run_timers(rt_clock);
    qemu_run_timers(host_clock);
}

static int64_t qemu_next_alarm_deadline(struct QEMUTimer **);

#ifdef _WIN32
static void CALLBACK host_alarm_handler(UINT uTimerID, UINT uMsg,
                                        DWORD_PTR dwUser, DWORD_PTR dw1,
                                        DWORD_PTR dw2)
#else
static void host_alarm_handler(int host_signum)
#endif
{
    struct qemu_alarm_timer *t = alarm_timer;
    if (!t)
	return;

#if 0
#define DISP_FREQ 1000
    {
        static int64_t delta_min = INT64_MAX;
        static int64_t delta_max, delta_cum, last_clock, delta, ti;
        static int count;
        ti = qemu_get_clock(vm_clock);
        if (last_clock != 0) {
            delta = ti - last_clock;
            if (delta < delta_min)
                delta_min = delta;
            if (delta > delta_max)
                delta_max = delta;
            delta_cum += delta;
            if (++count == DISP_FREQ) {
                printf("timer: min=%" PRId64 " us max=%" PRId64 " us avg=%" PRId64 " us avg_freq=%0.3f Hz\n",
                       muldiv64(delta_min, 1000000, get_ticks_per_sec()),
                       muldiv64(delta_max, 1000000, get_ticks_per_sec()),
                       muldiv64(delta_cum, 1000000 / DISP_FREQ, get_ticks_per_sec()),
                       (double)get_ticks_per_sec() / ((double)delta_cum / DISP_FREQ));
                count = 0;
                delta_min = INT64_MAX;
                delta_max = 0;
                delta_cum = 0;
            }
        }
        last_clock = ti;
    }
#endif
    if (alarm_has_dynticks(t) ||
        qemu_next_alarm_deadline (NULL) <= 0) {
        t->expired = alarm_has_dynticks(t);
        t->pending = 1;
        qemu_notify_event();
    }
}

int64_t qemu_next_deadline(void)
{
    /* To avoid problems with overflow limit this to 2^32.  */
    int64_t delta = INT32_MAX;

    if (active_timers[QEMU_CLOCK_VIRTUAL]) {
        delta = active_timers[QEMU_CLOCK_VIRTUAL]->expire_time -
                     qemu_get_clock_ns(vm_clock);
    }
    if (active_timers[QEMU_CLOCK_HOST]) {
        int64_t hdelta = active_timers[QEMU_CLOCK_HOST]->expire_time -
                 qemu_get_clock_ns(host_clock);
        if (hdelta < delta)
            delta = hdelta;
    }

    if (delta < 0)
        delta = 0;

    return delta;
}

static int64_t qemu_next_alarm_deadline(struct QEMUTimer **tp)
{
    int64_t delta;
    int64_t rtdelta;
    struct QEMUTimer *t;

    if (tp == NULL)
        tp = &t;

    if (!use_icount && active_timers[QEMU_CLOCK_VIRTUAL]) {
        delta = active_timers[QEMU_CLOCK_VIRTUAL]->expire_time -
                     qemu_get_clock(vm_clock);
        *tp = active_timers[QEMU_CLOCK_VIRTUAL];
    } else {
        delta = INT32_MAX;
        *tp = NULL;
    }
    if (active_timers[QEMU_CLOCK_HOST]) {
        int64_t hdelta = active_timers[QEMU_CLOCK_HOST]->expire_time -
                 qemu_get_clock_ns(host_clock);
        if (hdelta < delta) {
            delta = hdelta;
            *tp = active_timers[QEMU_CLOCK_HOST];
        }
    }

    if (active_timers[QEMU_CLOCK_REALTIME]) {
        rtdelta = (active_timers[QEMU_CLOCK_REALTIME]->expire_time * 1000000 -
                 qemu_get_clock_ns(rt_clock));
        if (rtdelta < delta) {
            delta = rtdelta;
            *tp = active_timers[QEMU_CLOCK_REALTIME];
        }
    }

    return delta;
}

#if defined(__linux__)

#define RTC_FREQ 1024

static void enable_sigio_timer(int fd)
{
    struct sigaction act;

    /* timer signal */
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGIO, &act, NULL);
    fcntl_setfl(fd, O_ASYNC);
    fcntl(fd, F_SETOWN, getpid());
}

static int hpet_start_timer(struct qemu_alarm_timer *t)
{
    struct hpet_info info;
    int r, fd;

    fd = qemu_open("/dev/hpet", O_RDONLY);
    if (fd < 0)
        return -1;

    /* Set frequency */
    r = ioctl(fd, HPET_IRQFREQ, RTC_FREQ);
    if (r < 0) {
        fprintf(stderr, "Could not configure '/dev/hpet' to have a 1024Hz timer. This is not a fatal\n"
                "error, but for better emulation accuracy type:\n"
                "'echo 1024 > /proc/sys/dev/hpet/max-user-freq' as root.\n");
        goto fail;
    }

    /* Check capabilities */
    r = ioctl(fd, HPET_INFO, &info);
    if (r < 0)
        goto fail;

    /* Enable periodic mode */
    r = ioctl(fd, HPET_EPI, 0);
    if (info.hi_flags && (r < 0))
        goto fail;

    /* Enable interrupt */
    r = ioctl(fd, HPET_IE_ON, 0);
    if (r < 0)
        goto fail;

    enable_sigio_timer(fd);
    t->priv = (void *)(long)fd;

    return 0;
fail:
    close(fd);
    return -1;
}

static void hpet_stop_timer(struct qemu_alarm_timer *t)
{
    int fd = (long)t->priv;

    close(fd);
}

static int rtc_start_timer(struct qemu_alarm_timer *t)
{
    int rtc_fd;
    unsigned long current_rtc_freq = 0;

    TFR(rtc_fd = qemu_open("/dev/rtc", O_RDONLY));
    if (rtc_fd < 0)
        return -1;
    ioctl(rtc_fd, RTC_IRQP_READ, &current_rtc_freq);
    if (current_rtc_freq != RTC_FREQ &&
        ioctl(rtc_fd, RTC_IRQP_SET, RTC_FREQ) < 0) {
        fprintf(stderr, "Could not configure '/dev/rtc' to have a 1024 Hz timer. This is not a fatal\n"
                "error, but for better emulation accuracy either use a 2.6 host Linux kernel or\n"
                "type 'echo 1024 > /proc/sys/dev/rtc/max-user-freq' as root.\n");
        goto fail;
    }
    if (ioctl(rtc_fd, RTC_PIE_ON, 0) < 0) {
    fail:
        close(rtc_fd);
        return -1;
    }

    enable_sigio_timer(rtc_fd);

    t->priv = (void *)(long)rtc_fd;

    return 0;
}

static void rtc_stop_timer(struct qemu_alarm_timer *t)
{
    int rtc_fd = (long)t->priv;

    close(rtc_fd);
}

#endif /* defined(__linux__) */

#if defined(__sun__)

#define QEMU_MULTITICKS_NSOURCES 8

int multiticks_enabled = 1;
int multiticks_tolerance_jitter = 20000;
int64_t multiticks_tolerance_interval = 200000;
int64_t multiticks_reap_threshold = NANOSEC;
int multiticks_reap_multiplier = 4;

struct multitick_source {
    timer_t source;
    QEMUTimer *timer;
    int64_t armed;
    int64_t interval;
    int64_t initial;
};

struct qemu_alarm_multiticks {
    int64_t reaped;
    struct multitick_source sources[QEMU_MULTITICKS_NSOURCES];
};

/*
 * Many QEMU timer consumers seek to create interval timers, but QEMU only has
 * a one-shot timer facility.  This forces the consumer to effect their own
 * intervals, an annoying (but not necessarily difficult) task. However, the
 * problem with using one-shots to implement interval timers is the overhead
 * of programming the underlying timer (e.g., timer_settime()):  even at
 * moderate frequencies (e.g., 1 KHz) this overhead can become significant at
 * modest levels of tenancy.  Given that the underlying POSIX timer facility
 * is in fact capable of providing interval timers (and given that using the
 * interval timers is more accurate than effecting the same with a one-shot),
 * and given that one can have multiple timers in a process, there is an
 * opportunity to significantly reduce timer programming overhead while
 * increasing timer accuracy by making better use of POSIX timers.  The
 * multiticks alarm timer does exactly this via a cache of interval timers,
 * associating a timer in a one-to-one manner with an underlying source.
 */
static int multiticks_start_timer(struct qemu_alarm_timer *t)
{
    struct sigevent ev;
    struct sigaction act;
    struct qemu_alarm_multiticks *multiticks;
    struct multitick_source *sources;
    struct itimerspec timeout;
    struct timespec res;
    int64_t resolution, found;
    int i;

    if (!multiticks_enabled) {
        fprintf(stderr, "multiticks: programmatically disabled\n");
        return -1;
    }

    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGALRM, &act, NULL);

    multiticks = qemu_mallocz(sizeof (struct qemu_alarm_multiticks));
    sources = multiticks->sources;
    t->priv = multiticks;

    memset(&ev, 0, sizeof(ev));
    ev.sigev_value.sival_int = 0;
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGALRM;

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++)
        sources[i].source = -1;

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
        if (timer_create(CLOCK_MONOTONIC, &ev, &sources[i].source) != 0) {
            perror("multiticks: timer_create");
            fprintf(stderr, "multiticks: could not create timer; disabling\n");
            multiticks_stop_timer(t);
            return -1;
        }
    }

    /*
     * Check that the implementation properly honors an arbitrary interval --
     * and in particular, an interval that is explicitly not evenly divided
     * by the resolution.  (Multiticks very much relies on interval timers
     * being properly implemented; even small errors in the interval can
     * add up quickly when frequencies are high.)
     */
    if (clock_getres(CLOCK_MONOTONIC, &res) != 0) {
        perror("multiticks: clock_getres");
        fprintf(stderr, "multiticks: could not get resolution; disabling\n");
        multiticks_stop_timer(t);
        return -1;
    }

    resolution = (res.tv_sec * NANOSEC + res.tv_nsec) * 60 * NANOSEC + 1;

    timeout.it_value.tv_sec = resolution / NANOSEC;
    timeout.it_value.tv_nsec = resolution % NANOSEC;
    timeout.it_interval.tv_sec = resolution / NANOSEC;
    timeout.it_interval.tv_nsec = resolution % NANOSEC;

    if (timer_settime(sources[0].source, TIMER_RELTIME, &timeout, NULL) != 0) {
        perror("multiticks: timer_settime");
        fprintf(stderr, "multiticks: could not set test timer; disabling\n");
        multiticks_stop_timer(t);
        return -1;
    }

    if (timer_gettime(sources[0].source, &timeout) != 0) {
        perror("multiticks: timer_gettime");
        fprintf(stderr, "multiticks: could not get test timer; disabling\n");
        multiticks_stop_timer(t);
        return -1;
    }

    found = timeout.it_interval.tv_sec * NANOSEC + timeout.it_interval.tv_nsec;

    if (resolution != found) {
        fprintf(stderr, "multitics: interval not properly honored "
            "(set to %lld; found %lld); disabling\n",
            (long long)resolution, (long long)found);
        multiticks_stop_timer(t);
        return -1;
    }

    memset(&timeout, 0, sizeof (timeout));
    (void) timer_settime(sources[0].source, TIMER_RELTIME, &timeout, NULL);

    return 0;
}

static void multiticks_stop_timer(struct qemu_alarm_timer *t)
{
    struct qemu_alarm_multiticks *multiticks = t->priv;
    struct multitick_source *sources = multiticks->sources;
    int i;

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
        if (sources[i].source != -1)
            timer_delete(sources[i].source); 
    }

    qemu_vfree(multiticks);
    t->priv = NULL;
}

static struct multitick_source *multiticks_source(struct qemu_alarm_timer *t,
                                                  QEMUTimer *timer)
{
    struct qemu_alarm_multiticks *multiticks = t->priv;
    struct multitick_source *sources = multiticks->sources, *source;
    int64_t oldest = INT64_MAX;
    int i;

    /*
     * We have a dynamic check here against multiticks_enabled to allow it
     * to be dynamically disabled after the multiticks alarm timer has been
     * configured.  When disabled, multiticks should degenerate to an
     * implementation approximating that of dynticks, allowing for behavior
     * comparisons to be made without restarting guests.
     */
    if (!multiticks_enabled) {
        source = &sources[0];
        source->interval = 0;
    } else {
        if ((source = timer->source) != NULL && source->timer == timer) {
            /*
             * This timer still owns its source -- it wasn't stolen since last
             * being armed.
             */
            return (source);
        }

        /*
         * The source has either been stolen from the timer, or it was never
         * assigned; find a source and assign it.
         */
        for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
            if (sources[i].armed < oldest) {
                oldest = sources[i].armed;
                source = &sources[i];
            }
        }
    }

    trace_multiticks_assign(source->timer, source->source);

    assert(source != NULL);
    source->timer = timer;
    timer->source = source;

    return (source);
}

static void multiticks_reap(struct qemu_alarm_timer *t, int64_t now)
{
    struct qemu_alarm_multiticks *multiticks = t->priv;
    struct multitick_source *sources = multiticks->sources, *source;
    int multiplier = multiticks_reap_multiplier;
    struct itimerspec timeout;
    int64_t interval;
    int i;

    if (now - multiticks->reaped < multiticks_reap_threshold)
        return;

    memset(&timeout, 0, sizeof (timeout));

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
        if (!(interval = sources[i].interval))
            continue;

        if (sources[i].armed + (multiplier * interval) > now)
            continue;

        source = &sources[i];
        trace_multiticks_reap(source->source, source->armed, interval);

        source->interval = 0;

        if (timer_settime(source->source, TIMER_RELTIME, &timeout, NULL) != 0) {
            perror("timer_settime");
            fprintf(stderr, "multiticks: internal reaping error; aborting\n");
            exit(1);
        }
    }

    multiticks->reaped = now;
}

static void multiticks_rearm_timer(struct qemu_alarm_timer *t)
{
    struct multitick_source *source;
    struct itimerspec timeout;
    QEMUTimer *timer;
    int64_t delta, when, interval;
    int64_t low, high, now;

    assert(alarm_has_dynticks(t));

    /*
     * First we need to find the next timer to fire.
     */
    low = get_clock();
    delta = qemu_next_alarm_deadline(&timer);
    now = high = get_clock();

    multiticks_reap(t, now);

    if (timer == NULL)
        return;

    low += delta;
    high += delta;

    if (timer->clock->type == QEMU_CLOCK_REALTIME) {
        interval = timer->interval * 1000000;
    } else {
        interval = timer->interval;
    }

    if (interval < multiticks_tolerance_interval)
        interval = 0;

    source = multiticks_source(t, timer);

    if (interval && source->interval) {
        int64_t offset, fire;

        if (low < source->initial && source->initial < high) {
            /*
             * Our timer has not yet had its initial firing, which is already
             * scheduled to be within band; we have nothing else to do.
             */
            trace_multiticks_inband(source->timer, low, high, source->initial);
            source->armed = now;
            return;
        }

        offset = (low - source->initial) % source->interval;
        fire = low + (source->interval - offset);

        if (fire < high) {
            /*
             * Our timer is going to fire within our band of expectation; we
             * have nothing else to do.
             */
            trace_multiticks_inband(source->timer, low, high, fire);
            source->armed = now;
            return;
        }

        if (fire - high < multiticks_tolerance_jitter) {
            /*
             * Our timer is going to fire out of our band of expection, but
             * within our jitter tolerance; we'll let it ride.
             */
            trace_multiticks_inband(source->timer, low, high, fire);
            source->armed = now;
            return;
        }

        trace_multiticks_outofband(source->timer, low, high, fire);
    }

    /*
     * We don't actually know the precise (absolute) time to fire, so we'll
     * take the middle of the band.
     */
    when = low + (high - low) / 2;

    trace_multiticks_program(source->timer, when, interval);

    source->interval = interval;
    source->armed = interval ? now : 0;
    source->initial = when;
    timeout.it_value.tv_sec = when / NANOSEC;
    timeout.it_value.tv_nsec = when % NANOSEC;
    timeout.it_interval.tv_sec = interval / NANOSEC;
    timeout.it_interval.tv_nsec = interval % NANOSEC;

    if (timer_settime(source->source, TIMER_ABSTIME, &timeout, NULL) != 0) {
        perror("timer_settime");
        fprintf(stderr, "multiticks: internal timer error; aborting\n");
        exit(1);
    }
}
#endif

#if defined(__linux__) || defined(__sun__)

static int dynticks_start_timer(struct qemu_alarm_timer *t)
{
    struct sigevent ev;
    timer_t host_timer;
    struct sigaction act;

    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGALRM, &act, NULL);

    /* 
     * Initialize ev struct to 0 to avoid valgrind complaining
     * about uninitialized data in timer_create call
     */
    memset(&ev, 0, sizeof(ev));
    ev.sigev_value.sival_int = 0;
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGALRM;

#if defined(__sun__)
    if (timer_create(CLOCK_HIGHRES, &ev, &host_timer)) {
#else
    if (timer_create(CLOCK_REALTIME, &ev, &host_timer)) {
#endif
        perror("timer_create");

        /* disable dynticks */
        fprintf(stderr, "Dynamic Ticks disabled\n");

        return -1;
    }

    t->priv = (void *)(long)host_timer;

    return 0;
}

static void dynticks_stop_timer(struct qemu_alarm_timer *t)
{
    timer_t host_timer = (timer_t)(long)t->priv;

    timer_delete(host_timer);
}

static void dynticks_rearm_timer(struct qemu_alarm_timer *t)
{
    timer_t host_timer = (timer_t)(long)t->priv;
    struct itimerspec timeout;
    int64_t nearest_delta_ns = INT64_MAX;
    int64_t current_ns;

    assert(alarm_has_dynticks(t));
    if (!active_timers[QEMU_CLOCK_REALTIME] &&
        !active_timers[QEMU_CLOCK_VIRTUAL] &&
        !active_timers[QEMU_CLOCK_HOST])
        return;

    nearest_delta_ns = qemu_next_alarm_deadline(NULL);
    if (nearest_delta_ns < MIN_TIMER_REARM_NS)
        nearest_delta_ns = MIN_TIMER_REARM_NS;

    /* check whether a timer is already running */
    if (timer_gettime(host_timer, &timeout)) {
        perror("gettime");
        fprintf(stderr, "Internal timer error: aborting\n");
        exit(1);
    }
    current_ns = timeout.it_value.tv_sec * 1000000000LL + timeout.it_value.tv_nsec;
    if (current_ns && current_ns <= nearest_delta_ns)
        return;

    timeout.it_interval.tv_sec = 0;
    timeout.it_interval.tv_nsec = 0; /* 0 for one-shot timer */
    timeout.it_value.tv_sec =  nearest_delta_ns / 1000000000;
    timeout.it_value.tv_nsec = nearest_delta_ns % 1000000000;
    if (timer_settime(host_timer, 0 /* RELATIVE */, &timeout, NULL)) {
        perror("settime");
        fprintf(stderr, "Internal timer error: aborting\n");
        exit(1);
    }
}

#endif /* defined(__linux__) || defined(__sun__) */

#if !defined(_WIN32)

static int unix_start_timer(struct qemu_alarm_timer *t)
{
    struct sigaction act;
    struct itimerval itv;
    int err;

    /* timer signal */
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGALRM, &act, NULL);

    itv.it_interval.tv_sec = 0;
    /* for i386 kernel 2.6 to get 1 ms */
    itv.it_interval.tv_usec = 999;
    itv.it_value.tv_sec = 0;
    itv.it_value.tv_usec = 10 * 1000;

    err = setitimer(ITIMER_REAL, &itv, NULL);
    if (err)
        return -1;

    return 0;
}

static void unix_stop_timer(struct qemu_alarm_timer *t)
{
    struct itimerval itv;

    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);
}

#endif /* !defined(_WIN32) */


#ifdef _WIN32

static int win32_start_timer(struct qemu_alarm_timer *t)
{
    TIMECAPS tc;
    struct qemu_alarm_win32 *data = t->priv;
    UINT flags;

    memset(&tc, 0, sizeof(tc));
    timeGetDevCaps(&tc, sizeof(tc));

    data->period = tc.wPeriodMin;
    timeBeginPeriod(data->period);

    flags = TIME_CALLBACK_FUNCTION;
    if (alarm_has_dynticks(t))
        flags |= TIME_ONESHOT;
    else
        flags |= TIME_PERIODIC;

    data->timerId = timeSetEvent(1,         // interval (ms)
                        data->period,       // resolution
                        host_alarm_handler, // function
                        (DWORD)t,           // parameter
                        flags);

    if (!data->timerId) {
        fprintf(stderr, "Failed to initialize win32 alarm timer: %ld\n",
                GetLastError());
        timeEndPeriod(data->period);
        return -1;
    }

    return 0;
}

static void win32_stop_timer(struct qemu_alarm_timer *t)
{
    struct qemu_alarm_win32 *data = t->priv;

    timeKillEvent(data->timerId);
    timeEndPeriod(data->period);
}

static void win32_rearm_timer(struct qemu_alarm_timer *t)
{
    struct qemu_alarm_win32 *data = t->priv;

    assert(alarm_has_dynticks(t));
    if (!active_timers[QEMU_CLOCK_REALTIME] &&
        !active_timers[QEMU_CLOCK_VIRTUAL] &&
        !active_timers[QEMU_CLOCK_HOST])
        return;

    timeKillEvent(data->timerId);

    data->timerId = timeSetEvent(1,
                        data->period,
                        host_alarm_handler,
                        (DWORD)t,
                        TIME_ONESHOT | TIME_CALLBACK_FUNCTION);

    if (!data->timerId) {
        fprintf(stderr, "Failed to re-arm win32 alarm timer %ld\n",
                GetLastError());

        timeEndPeriod(data->period);
        exit(1);
    }
}

#endif /* _WIN32 */

static void alarm_timer_on_change_state_rearm(void *opaque, int running, int reason)
{
    if (running)
        qemu_rearm_alarm_timer((struct qemu_alarm_timer *) opaque);
}

int init_timer_alarm(void)
{
    struct qemu_alarm_timer *t = NULL;
    int i, err = -1;

    for (i = 0; alarm_timers[i].name; i++) {
        t = &alarm_timers[i];

        err = t->start(t);
        if (!err)
            break;
    }

    if (err) {
        err = -ENOENT;
        goto fail;
    }

    /* first event is at time 0 */
    t->pending = 1;
    alarm_timer = t;
    qemu_add_vm_change_state_handler(alarm_timer_on_change_state_rearm, t);

    return 0;

fail:
    return err;
}

void quit_timers(void)
{
    struct qemu_alarm_timer *t = alarm_timer;
    alarm_timer = NULL;
    t->stop(t);
}

int qemu_calculate_timeout(void)
{
    int timeout;

#define QEMUKVM 1
#if defined (CONFIG_IOTHREAD) || defined (QEMUKVM)
    /* When using icount, making forward progress with qemu_icount when the
       guest CPU is idle is critical. We only use the static io-thread timeout
       for non icount runs.  */
    if (!use_icount) {
        return 1000;
    }
#endif

    if (!vm_running)
        timeout = 5000;
    else {
     /* XXX: use timeout computed from timers */
        int64_t add;
        int64_t delta;
        /* Advance virtual time to the next event.  */
	delta = qemu_icount_delta();
        if (delta > 0) {
            /* If virtual time is ahead of real time then just
               wait for IO.  */
            timeout = (delta + 999999) / 1000000;
        } else {
            /* Wait for either IO to occur or the next
               timer event.  */
            add = qemu_next_deadline();
            /* We advance the timer before checking for IO.
               Limit the amount we advance so that early IO
               activity won't get the guest too far ahead.  */
            if (add > 10000000)
                add = 10000000;
            delta += add;
            qemu_icount += qemu_icount_round (add);
            timeout = delta / 1000000;
            if (timeout < 0)
                timeout = 0;
        }
    }

    return timeout;
}

