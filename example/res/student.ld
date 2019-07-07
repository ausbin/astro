SECTIONS {
    . = 0x3000;
    .text ALIGN(0x1000): { *(.text) }

    /* 4k guard */
    . += 0x1000;

    .rodata ALIGN(0x1000): { *(.rodata) }
    .bss ALIGN(0x1000): { *(.bss) }

    /* 4k guard */
    . += 0x1000;
    __heap_start = ALIGN(0x1000);
}
