SECTIONS {
    . = 0x3000;
    .text ALIGN(0x1000): { *(.text) }

    /* 4k guard against geniuses */
    . += 0x1000;
    .data ALIGN(0x1000): { *(.data) }
    .bss ALIGN(0x1000): { *(.bss) }
}
