// SPDX-License-Identifier: GPL-2.0+
/* TODO:
 * - Should we enwrap the status line in ESC-markers
 *   for userspace to be able to uniquely identify it?
 *   E. g. userspace could visually distinguish and/or
 *   localize included text.
 *
 * - While gathering intel on mit, should we lock it somehow?
 *
 * - We need to implement an actual better_proc algorithm.
 *
 * - Should we differentiate between TIDs in same thread group?
 */

#include <linux/kallsyms.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/cputime.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/tty.h>

#define task_pid_vlnr(t) task_pid_nr_ns((t), ns_of_pid(task_pid((t))))

#define BCOMPARE(lbool, rbool) ((lbool) << 1 | (rbool))
#define BCOMPARE_NONE 0
#define BCOMPARE_RIGHT 1
#define BCOMPARE_LEFT 2
#define BCOMPARE_BOTH (BCOMPARE_LEFT | BCOMPARE_RIGHT)

/*
 * Select the most interesting task of two.
 *
 * The implemented approach is simple for now:
 * - pick runnable
 * - if no runnables, pick uninterruptible
 * - if tie between runnables, pick highest utime + stime
 * - if a tie is not broken by the above, pick highest pid nr.
 *
 * Here's the one used in FreeBSD:
 * - pick runnables over anything
 * - if both runnables, pick highest cpu utilization
 * - if no runnables, pick shortest sleep time
 * - other ties are decided in favour of youngest process.
 */
static struct task_struct *__better_proc_R(struct task_struct *a,
		struct task_struct *b)
{
	unsigned long flags;
	u64 atime, btime, tgutime, tgstime;
	struct task_struct *ret;

	if (!lock_task_sighand(a, &flags))
		goto out_a_unlocked;
	thread_group_cputime_adjusted(a, &tgutime, &tgstime);
	atime = tgutime + tgstime;
	unlock_task_sighand(a, &flags);

	if (!lock_task_sighand(b, &flags))
		goto out_b_unlocked;
	thread_group_cputime_adjusted(b, &tgutime, &tgstime);
	btime = tgutime + tgstime;
	unlock_task_sighand(b, &flags);

	ret = atime > btime ? a : b;

	return ret;

out_b_unlocked:
out_a_unlocked:
	return task_pid_vlnr(a) > task_pid_vlnr(b) ? a : b;
}

static struct task_struct *__better_proc(struct task_struct *a,
		struct task_struct *b)
{
	if (!pid_alive(a))
		return b;
	if (!pid_alive(b))
		return a;

	switch (BCOMPARE(a->state == TASK_RUNNING,
			b->state == TASK_RUNNING)) {
	case BCOMPARE_LEFT:
		return a;
	case BCOMPARE_RIGHT:
		return b;
	case BCOMPARE_BOTH:
		return __better_proc_R(a, b);
	}

	switch (BCOMPARE(a->state == TASK_UNINTERRUPTIBLE,
			b->state == TASK_UNINTERRUPTIBLE)) {
	case BCOMPARE_LEFT:
		return a;
	case BCOMPARE_RIGHT:
		return b;
	case BCOMPARE_BOTH:
		break;
	}

	/* TODO: Perhaps we should check something else... */
	return task_pid_vlnr(a) > task_pid_vlnr(b) ? a : b;
}

/*
 * Weed out NULLs.
 * a and b are pointers to (struct task_struct); therefore no problem
 * with triple evaluation.
 */
#define better_proc(a, b) ((a) ? ((b) ? __better_proc((a), (b)) : (a)) : (b))

static int scnprint_load(char *msgp, size_t size)
{
	unsigned long la[3];

	get_avenrun(la, FIXED_1/200, 0);
	return scnprintf(msgp, size, "load: %lu.%02lu; ",
			LOAD_INT(la[0]), LOAD_FRAC(la[0]));
}

static int scnprint_task(char *msgp, size_t size, struct task_struct *task)
{
	char commname[TASK_COMM_LEN];

	get_task_comm(commname, task);
	return scnprintf(msgp, size, "%d/%s:", task_pid_vlnr(task), commname);
}

static int scnprint_rusage(char *msgp, ssize_t size,
		struct task_struct *task, struct mm_struct *mm)
{
	struct rusage ru;
	struct timeval utime, stime;
	struct timespec rtime;
	u64 now;
	int ret = 0;
	int psz = 0;

	getrusage(task, RUSAGE_BOTH, &ru);
	now = ktime_get_ns();

	utime = ru.ru_utime;
	stime = ru.ru_stime;
	rtime.tv_nsec = now - task->start_time;
	rtime.tv_sec = rtime.tv_nsec / 1000000000;
	rtime.tv_nsec %= 1000000000;

	psz = scnprintf(msgp, size,
			"%lu.%03lur %lu.%03luu %lu.%03lus",
			rtime.tv_sec, rtime.tv_nsec / 1000000,
			utime.tv_sec, utime.tv_usec / 1000,
			stime.tv_sec, stime.tv_usec / 1000);
	ret += psz;
	msgp += psz;
	size -= psz;

	if (mm) {
		psz = scnprintf(msgp, size,
				" %luk/%luk",
				get_mm_rss(mm) * PAGE_SIZE / 1024,
				get_mm_hiwater_rss(mm) * PAGE_SIZE / 1024);
		ret += psz;
	}
	return ret;
}

static int scnprint_state(char *msgp, ssize_t size,
		struct task_struct *task, struct mm_struct *mm)
{
	char stat[8] = {0};
	const char *state_descr = "";
	unsigned long wchan = 0;
	int psz = 0;
	char symname[KSYM_NAME_LEN];

	stat[psz++] = task_state_to_char(task);
	if (task_nice(task) < 0)
		stat[psz++] = '<';
	else if (task_nice(task) > 0)
		stat[psz++] = 'N';
	if (mm && mm->locked_vm)
		stat[psz++] = 'L';
	if (get_nr_threads(task) > 1)
		stat[psz++] = 'l';

	switch (stat[0]) {
	case 'R':
		if (task_curr(task))
			stat[psz++] = '!';
		break;
	case 'S':
	case 'D':
		wchan = get_wchan(task);
		if (!wchan)
			break;
		if (!lookup_symbol_name(wchan, symname))
			state_descr = symname;
		else
			state_descr = "*unknown*";
		break;
	case 'T':
		state_descr = "stopped";
		break;
	case 't':
		state_descr = "traced";
		break;
	case 'Z':
		psz = sprintf(symname, "zombie; ppid=%d",
			task_tgid_nr_ns(task->real_parent,
				ns_of_pid(task_pid(task))));
		if (task->parent != task->real_parent)
			sprintf(symname + psz, " reaper=%d",
				task_tgid_nr_ns(task->parent,
					ns_of_pid(task_pid(task))));
		state_descr = symname;
		break;
	case 'I':
		/* Can this even happen? */
		state_descr = "idle";
		break;
	default:
		state_descr = "unknown";
	}

	psz = scnprintf(msgp, size, "%s", stat);
	msgp += psz;
	size -= psz;
	if (*state_descr)
		psz += scnprintf(msgp, size, wchan ? " [%s]" : " (%s)", state_descr);

	return psz;
}

/**
 *	tty_sprint_status_line	-		produce kerninfo line
 *	@tty: terminal device
 *	@msg: preallocated memory buffer
 *	@length: maximum line length
 *
 *	Reports state of foreground process group in a null-terminated string
 *	located at @msg, @length bytes long. If @length is insufficient,
 *	the line gets truncated.
 */
void tty_sprint_status_line(struct tty_struct *t, char *msg, size_t length)
{
	struct task_struct *tsk = NULL, *mit = NULL;
	struct mm_struct *mm;
	struct pid *pgrp = NULL;
	char *msgp = msg;
	int psz = 0;

	if (!length)
		return;
	length--; /* Make room for trailing '\n' */

	psz = scnprint_load(msgp, length);
	if (psz > 0) {
		msgp += psz;
		length -= psz;
	}
	if (!length)
		goto finalize_message;

	/* Not sure if session pid is protected by ctrl_lock
	 * or tasklist_lock...
	 */
	pgrp = t->session;
	if (pgrp == NULL) {
		psz = scnprintf(msgp, length, "not a controlling tty");
		if (psz > 0)
			msgp += psz;
		goto finalize_message;
	}
	pgrp = tty_get_pgrp(t);
	if (pgrp == NULL) {
		psz = scnprintf(msgp, length, "no foreground process group");
		if (psz > 0)
			msgp += psz;
		goto finalize_message;
	}
	/* empty foreground pgid check? */

	/* If TTYSL_ENUMERATE_PGRP is defined,
	 * just enumerate all processes in foreground process group
	 * for now for debugging purposes.
	 */
	read_lock(&tasklist_lock);
	do_each_pid_task(pgrp, PIDTYPE_PGID, tsk)
	{
		/* Select the most interesting task. */
		if (tsk == better_proc(mit, tsk))
			mit = tsk;
#ifdef TTYSL_ENUMERATE_PGRP
		psz = sprintf(msgp, "%d, ", task_pid_vlnr(tsk));
		if (psz > 0)
			msgp += psz;
#endif
	} while_each_pid_task(pgrp, PIDTYPE_PGID, tsk);
	read_unlock(&tasklist_lock);
#ifdef TTYSL_ENUMERATE_PGRP
	msgp -= 2;
	*msgp++ = ';';
	*msgp++ = ' ';
#endif

	if (!pid_alive(mit))
		goto finalize_message;

	/* Gather intel on most interesting task. */
	/* Can the mm of a foreground process turn out to be NULL?
	 * Definitely; for example, if it is a zombie.
	 */
	mm = get_task_mm(mit);

	psz = scnprint_task(msgp, length, mit);
	if (psz > 0) {
		msgp += psz;
		length -= psz;
	}
	if (!length)
		goto finalize_message;
	*msgp++ = ' ';
	length--;

	psz = scnprint_state(msgp, length, mit, mm);
	if (psz > 0) {
		msgp += psz;
		length -= psz;
	}
	if (!length)
		goto finalize_message;
	*msgp++ = ' ';
	length--;

	psz = scnprint_rusage(msgp, length, mit, mm);
	if (psz > 0) {
		msgp += psz;
		length -= psz;
	}
	if (!length)
		goto finalize_message;
	*msgp++ = ' ';
	length--;

	if (!mm)
		goto finalize_message;

	mmput(mm);

finalize_message:
	*msgp++ = '\n';
	if (pgrp)
		put_pid(pgrp);
}
