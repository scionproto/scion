function ConfigureLocal()
    autocmd! BufWritePost * Neomake

    " Disable the syntastic checkers
    let g:syntastic_cpp_checkers = []
    let g:syntastic_c_checkers = []

    " Configure deoplete-clang
    let g:deoplete#sources#clang#clang_complete_database = getcwd()

    " Configure makers
    let g:neomake_c_enabled_makers = ['clangcheck', 'clangtidy']
    let g:neomake_cpp_enabled_makers = ['clangcheck', 'clangtidy']
    let g:neomake_cpp_clangcheck_args = ['%:p', '-analyze']
    let g:neomake_cpp_clangtidy_args = ['-checks=-*,cert-*,cppcoreguidelines-*,clang-analyzer-*,misc-*,performance-*,readability-*']
endfunction

autocmd FileType cpp call ConfigureLocal()
autocmd FileType c call ConfigureLocal()
