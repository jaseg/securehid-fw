#ifndef __TRACING_H__
#define __TRACING_H__

#include <libopencm3/stm32/gpio.h>

#ifndef VERIFICATION
#define TRACING_SET(i) gpio_set(GPIOD, (1<<i))
#define TRACING_CLEAR(i) gpio_clear(GPIOD, (1<<i))
#else
#define TRACING_SET(i) ((void)0)
#define TRACING_CLEAR(i) ((void)0)
#endif

enum tracing_channels {
    TR_HID_MESSAGE_HANDLER = 0,
    TR_DEBUG_OUT_DMA_IRQ = 1,
    TR_HOST_IF_DMA_IRQ = 2,
    TR_HOST_IF_USART_IRQ = 3,
    TR_USBH_POLL = 4,
    TR_HOST_PKT_HANDLER = 5,
    TR_NOISE_HANDSHAKE = 6,
    TR_RNG = 7,
};

#endif
