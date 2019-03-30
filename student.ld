SECTIONS {
    . = 0x3000;
    .text ALIGN(0x1000): { user/start.o(.text) *(.text) }

    /* 4k guard */
    . += 0x1000;

    .data ALIGN(0x1000): { *(.data) }
    .bss ALIGN(0x1000): { *(.bss) }

    /* 4k guard */
    . += 0x1000;
    __heap_start = ALIGN(0x1000);
}
