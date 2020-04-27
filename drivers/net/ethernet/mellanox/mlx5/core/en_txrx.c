/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if defined(HAVE_IRQ_DESC_GET_IRQ_DATA) && defined(HAVE_IRQ_TO_DESC_EXPORTED)
#include <linux/irq.h>
#endif
#include "en.h"
#include "en/xdp.h"
#include "en/txrx.h"

#if defined(HAVE_IRQ_DESC_GET_IRQ_DATA) && defined(HAVE_IRQ_TO_DESC_EXPORTED)
static inline bool mlx5e_channel_no_affinity_change(struct mlx5e_channel *c)
{
	int current_cpu = smp_processor_id();
	const struct cpumask *aff;
#ifndef HAVE_IRQ_DATA_AFFINITY
	struct irq_data *idata;

	idata = irq_desc_get_irq_data(c->irq_desc);
	aff = irq_data_get_affinity_mask(idata);
#else
	aff = irq_desc_get_irq_data(c->irq_desc)->affinity;
#endif
	return cpumask_test_cpu(current_cpu, aff);
}
#endif

static void mlx5e_handle_tx_dim(struct mlx5e_txqsq *sq)
{
	struct net_dim_sample *sample = &sq->dim_obj.sample;

	if (unlikely(!test_bit(MLX5E_SQ_STATE_AM, &sq->state)))
		return;

	net_dim_sample(sq->cq.event_ctr, sample->pkt_ctr, sample->byte_ctr, sample);
	net_dim(&sq->dim_obj.dim, *sample);
}

static void mlx5e_handle_rx_dim(struct mlx5e_rq *rq)
{
	struct net_dim_sample *sample = &rq->dim_obj.sample;

	if (unlikely(!test_bit(MLX5E_RQ_STATE_AM, &rq->state)))
		return;

	net_dim_sample(rq->cq.event_ctr, sample->pkt_ctr, sample->byte_ctr, sample);
	net_dim(&rq->dim_obj.dim, *sample);
}

void mlx5e_trigger_irq(struct mlx5e_icosq *sq)
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5e_tx_wqe *nopwqe;
	u16 pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);

	sq->db.ico_wqe[pi].opcode = MLX5_OPCODE_NOP;
	nopwqe = mlx5e_post_nop(wq, sq->sqn, &sq->pc);
	mlx5e_notify_hw(wq, sq->pc, sq->uar_map, &nopwqe->ctrl);
}

int mlx5e_napi_poll(struct napi_struct *napi, int budget)
{
	struct mlx5e_channel *c = container_of(napi, struct mlx5e_channel,
					       napi);
	struct mlx5e_ch_stats *ch_stats = c->stats;
	struct mlx5e_rq *rq = &c->rq;
	bool busy = false;
	int work_done = 0;
	int i;

	ch_stats->poll++;
#ifndef HAVE_NAPI_STATE_MISSED
	clear_bit(MLX5E_CHANNEL_NAPI_SCHED, &c->flags);
#endif

	for (i = 0; i < c->num_tc; i++)
		busy |= mlx5e_poll_tx_cq(&c->sq[i].cq, budget);

#ifdef CONFIG_MLX5_EN_SPECIAL_SQ
	for (i = 0; i < c->num_special_sq; i++)
		busy |= mlx5e_poll_tx_cq(&c->special_sq[i].cq, budget);
#endif

#ifdef HAVE_XDP_REDIRECT
       busy |= mlx5e_poll_xdpsq_cq(&c->xdpsq.cq, NULL);
#endif

#ifdef HAVE_XDP_BUFF
       if (c->xdp)
       	busy |= mlx5e_poll_xdpsq_cq(&rq->xdpsq.cq, rq);
#endif

	if (likely(budget)) { /* budget=0 means: don't poll rx rings */
		work_done = mlx5e_poll_rx_cq(&rq->cq, budget);
		busy |= work_done == budget;
	}

	busy |= c->rq.post_wqes(rq);

#if defined(HAVE_IRQ_DESC_GET_IRQ_DATA) && defined(HAVE_IRQ_TO_DESC_EXPORTED)
	if (busy) {
		if (likely(mlx5e_channel_no_affinity_change(c)))
			return budget;
		ch_stats->aff_change++;
		if (budget && work_done == budget)
			work_done--;
	}
#else
	if (busy)
		return budget;
#endif

#ifdef HAVE_NAPI_STATE_MISSED 
	if (unlikely(!napi_complete_done(napi, work_done)))
		return work_done;
#else
 	napi_complete_done(napi, work_done);
 
 	/* avoid losing completion event during/after polling cqs */
	if (test_bit(MLX5E_CHANNEL_NAPI_SCHED, &c->flags)) {
		napi_schedule(napi);
		return work_done;
	}
#endif

	ch_stats->arm++;

	for (i = 0; i < c->num_tc; i++) {
		mlx5e_handle_tx_dim(&c->sq[i]);
		mlx5e_cq_arm(&c->sq[i].cq);
	}

#ifdef CONFIG_MLX5_EN_SPECIAL_SQ
	for (i = 0; i < c->num_special_sq; i++)
		mlx5e_cq_arm(&c->special_sq[i].cq);
#endif

	mlx5e_handle_rx_dim(rq);

	mlx5e_cq_arm(&rq->cq);
	mlx5e_cq_arm(&c->icosq.cq);
#ifdef HAVE_XDP_REDIRECT
	mlx5e_cq_arm(&c->xdpsq.cq);
#endif

	return work_done;
}

void mlx5e_completion_event(struct mlx5_core_cq *mcq, struct mlx5_eqe *eqe)
{
	struct mlx5e_cq *cq = container_of(mcq, struct mlx5e_cq, mcq);

#ifndef HAVE_NAPI_STATE_MISSED
	set_bit(MLX5E_CHANNEL_NAPI_SCHED, &cq->channel->flags);
#endif
	napi_schedule(cq->napi);
	cq->event_ctr++;
	cq->channel->stats->events++;
}

void mlx5e_cq_error_event(struct mlx5_core_cq *mcq, enum mlx5_event event)
{
	struct mlx5e_cq *cq = container_of(mcq, struct mlx5e_cq, mcq);
	struct mlx5e_channel *c = cq->channel;
	struct net_device *netdev = c->netdev;

	netdev_err(netdev, "%s: cqn=0x%.6x event=0x%.2x\n",
		   __func__, mcq->cqn, event);
}
