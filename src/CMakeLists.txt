set (inc ${CMAKE_SOURCE_DIR}/include)

add_library (usbhost
	${USART_HELPERS}
	${inc}/usbh_core.h
	${inc}/usbh_driver_ac_midi.h
	${inc}/usbh_driver_gp_xbox.h
	${inc}/usbh_driver_hid.h
	${inc}/usbh_driver_hub.h
	${inc}/usbh_lld_stm32f4.h
	${inc}/driver/usbh_device_driver.h
	${inc}/usbh_config.h

	usbh_core.c
	usbh_driver_ac_midi.c
	usbh_driver_ac_midi_private.h
	usbh_driver_gp_xbox.c
	usbh_driver_hid.c
	usbh_driver_hub.c
	usbh_driver_hub_private.h
	usbh_lld_stm32f4.c
    usart_helpers.c
    tinyprintf.c
    cobs.c
    noise.c
    packet_interface.c
    words.c
    hid_keycodes.c
)

add_subdirectory (crypto)

add_definitions (
    -DBLAKE2S_USE_VECTOR_MATH=0
)

target_link_libraries (usbhost
    noise
	${LIBOPENCM3_LIB}
)

add_executable (demo
    rand_stm32.c
	demo.c
)

target_link_libraries (demo
	usbhost
    noise
)

add_custom_command (TARGET demo
	POST_BUILD
	COMMAND ${CMAKE_OBJCOPY} -Oihex $<TARGET_FILE:demo> ${CMAKE_BINARY_DIR}/demo.hex
	COMMENT "Generating output files: ${CMAKE_BINARY_DIR}/demo.hex"
)

add_custom_command (TARGET demo
	POST_BUILD
	COMMAND ${CMAKE_SIZE} $<TARGET_FILE:demo>
	COMMENT "Calculating size of the binary"
)

add_custom_command (TARGET usbhost
	POST_BUILD
	COMMENT "Calculating size of the library"
	COMMAND ${CMAKE_SIZE} $<TARGET_FILE:usbhost>
)

