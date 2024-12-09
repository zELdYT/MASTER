
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_QUANTUM_INCLUDE_H__
#define __MASTER_QUANTUM_INCLUDE_H__

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "../hypercomplex/complex.h"

typedef struct {
	MASTER_complexd alpha; // Amplitude state |0>
	MASTER_complexd beta;  // Amplitude state |1>
} MASTER_Qubit;

MASTER_Qubit
MASTER_Qubit_init(void) {
	MASTER_Qubit __q;
	__q.alpha.real = 1.0;
	__q.alpha.imag = 0.0;
	__q.beta.real  = 1.0;
	__q.beta.imag  = 0.0;
	return __q;
}

double
MASTER_Qubit_get(MASTER_Qubit * const __q) {
	double random_value = (double)rand() / RAND_MAX;
	
	if (random_value < pow(__q->alpha.real, 2) + pow(__q->alpha.imag, 2)) {
		__q->alpha = MASTER_complex_toComplexd(1.0);
		__q->beta  = MASTER_complex_toComplexd(0.0);
		return 0;
	} else {
		__q->alpha = MASTER_complex_toComplexd(0.0);
		__q->beta  = MASTER_complex_toComplexd(1.0);
		return 1;
	}
}

void
MASTER_Qubit_set(MASTER_Qubit * const __q, double alpha, double beta) {
	__q->alpha = MASTER_complex_toComplexd(alpha);
	__q->beta = MASTER_complex_toComplexd(beta);
}

void
MASTER_Qubit_PauliX(MASTER_Qubit * const __q) {
	MASTER_complexd buf = __q->alpha;
	__q->alpha = __q->beta;
	__q->beta = buf;
}

void
MASTER_Qubit_PauliY(MASTER_Qubit * const __q) {
	MASTER_complexd temp = __q->alpha, part;
	part = MASTER_complex_toComplexExtd(0.0, 1.0);
	__q->alpha = MASTER_complex_muld(&part, &__q->beta);
	part = MASTER_complex_toComplexExtd(0.0, -1.0);
	__q->beta = MASTER_complex_muld(&part, &temp);
}

void
MASTER_Qubit_PauliZ(MASTER_Qubit * const __q) {
	MASTER_complexd t = MASTER_complex_toComplexExtd(-1.0, 0.0);
	__q->beta = MASTER_complex_muld(&t, &__q->beta);
}

void
MASTER_Qubit_Hadamar(MASTER_Qubit * const __q) {
	MASTER_complexd alpha_new = MASTER_complex_toComplexd( (__q->alpha.real + __q->beta.real) / sqrt(2) );
	MASTER_complexd beta_new = MASTER_complex_toComplexd( (__q->alpha.real - __q->beta.real) / sqrt(2) );
	
	__q->alpha = alpha_new;
	__q->beta = beta_new;
}

void
MASTER_Qubit_PhaseShift(MASTER_Qubit * const __q, const double phi) {
	__q->beta.real = cos(phi) * __q->beta.real - sin(phi) * __q->beta.imag;
	__q->beta.imag = sin(phi) * __q->beta.real + cos(phi) * __q->beta.imag;
}

void
MASTER_Qubit_Rx(MASTER_Qubit * const __q, const double theta) {
	MASTER_complexd alpha_new;
	MASTER_complexd beta_new;
	
	double sin_theta = sin(theta / 2.0), cos_theta = cos(theta / 2.0);
	alpha_new.real = cos_theta * __q->alpha.real + sin_theta * __q->beta.imag;
	alpha_new.imag = cos_theta * __q->alpha.imag - sin_theta * __q->beta.real;

	beta_new.real = -sin_theta * __q->alpha.imag + cos_theta * __q->beta.real;
	beta_new.imag = sin_theta * __q->alpha.real + cos_theta * __q->beta.imag;

	__q->alpha = alpha_new;
	__q->beta = beta_new;
}

void
MASTER_Qubit_Ry(MASTER_Qubit * const __q, const double theta) {
	MASTER_complexd alpha_new;
	MASTER_complexd beta_new;

	double sin_theta = sin(theta / 2.0), cos_theta = cos(theta / 2.0);
	alpha_new.real = cos_theta * __q->alpha.real - sin_theta * __q->beta.real;
	alpha_new.imag = cos_theta * __q->alpha.imag - sin_theta * __q->beta.imag;

	beta_new.real = sin_theta * __q->alpha.real + cos_theta * __q->beta.real;
	beta_new.imag = sin_theta * __q->alpha.imag + cos_theta * __q->beta.imag;

	__q->alpha = alpha_new;
	__q->beta = beta_new;
}

void
MASTER_Qubit_Rz(MASTER_Qubit * const __q, double theta) {
	double sin_theta = sin(theta / 2.0), cos_theta = cos(theta / 2.0);
	__q->alpha.real = cos_theta * __q->alpha.real + sin_theta * __q->alpha.imag;
	__q->alpha.imag = -sin_theta * __q->alpha.real + cos_theta * __q->alpha.imag;

	__q->beta.real = cos_theta * __q->beta.real - sin_theta * __q->beta.imag;
	__q->beta.imag = sin_theta * __q->beta.real + cos_theta * __q->beta.imag;
}

void
MASTER_Qubit_Swap(MASTER_Qubit * const __q1, MASTER_Qubit * const __q2) {
	MASTER_complexd temp = __q1->alpha;
	__q1->alpha = __q2->alpha;
	__q2->alpha = temp;

	temp = __q1->beta;
	__q1->beta = __q2->beta;
	__q2->beta = temp;
}

void
MASTER_Qubit_CNOT(MASTER_Qubit * const control, MASTER_Qubit * const target) {
	double prob_one = control->beta.real * control->beta.real + control->beta.imag * control->beta.imag;
	double random_value = (double)rand() / RAND_MAX;
	if (random_value < prob_one) {
		MASTER_complexd targetAlphaBuf = target->alpha;
		target->alpha = target->beta;
		target->beta = targetAlphaBuf;
	}
}

void
MASTER_Qubit_Toffoli(MASTER_Qubit * const control1, MASTER_Qubit * const control2, MASTER_Qubit * const target) {
	if (control1->alpha.real != 0 && control1->alpha.imag != 0 &&
		control2->alpha.real != 0 && control2->alpha.imag != 0 &&
		(target->alpha.real != 0 || target->alpha.imag != 0)) {
		MASTER_complexd targetAlphaBuf = target->alpha;
		target->alpha = target->beta;
		target->beta = targetAlphaBuf;
	}
}

void
MASTER_Qubit_ControlledU(MASTER_Qubit * const control, MASTER_Qubit * const target, void (*U)(MASTER_Qubit * const)) {
	if (control->alpha.real != 0 || control->alpha.imag != 0) U(target);
}



typedef struct {
	MASTER_complexd alpha; // Amplitude state |0⟩
	MASTER_complexd beta;  // Amplitude state |1⟩
	MASTER_complexd gamma; // Amplitude state |2⟩
} MASTER_Qutrit;

MASTER_Qutrit
MASTER_Qutrit_init(void) {
	MASTER_Qutrit q;
	q.alpha = MASTER_complex_toComplexd(1.0);
	q.beta = MASTER_complex_toComplexd(0.0);
	q.gamma = MASTER_complex_toComplexd(0.0);
	return q;
}

int
MASTER_Qutrit_get(MASTER_Qutrit * const q) {
	double p0 = pow(q->alpha.real, 2) + pow(q->alpha.imag, 2);
	double p1 = pow(q->beta.real, 2) + pow(q->beta.imag, 2);
	double random_value = (double)rand() / RAND_MAX;

	if (random_value < p0) {
		q->alpha = MASTER_complex_toComplexd(1.0);
		q->beta = MASTER_complex_toComplexd(0.0);
		q->gamma = MASTER_complex_toComplexd(0.0);
		return 0;
	} else if (random_value < p0 + p1) {
		q->alpha = MASTER_complex_toComplexd(0.0);
		q->beta = MASTER_complex_toComplexd(1.0);
		q->gamma = MASTER_complex_toComplexd(0.0);
		return 1;
	} else {
		q->alpha = MASTER_complex_toComplexd(0.0);
		q->beta = MASTER_complex_toComplexd(0.0);
		q->gamma = MASTER_complex_toComplexd(1.0);
		return 2;
	}
}

void
MASTER_Qutrit_set(MASTER_Qutrit * const q, const double alpha, const double beta, const double gamma) {
	q->alpha = MASTER_complex_toComplexd(alpha);
	q->beta = MASTER_complex_toComplexd(beta);
	q->gamma = MASTER_complex_toComplexd(gamma);
}

void
MASTER_Qutrit_PauliX(MASTER_Qutrit * const q) {
	MASTER_complexd temp = q->alpha;
	q->alpha = q->gamma;
	q->gamma = q->beta;
	q->beta = temp;
}

#endif /* __MASTER_QUANTUM_INCLUDE_H__ */

// be master~
