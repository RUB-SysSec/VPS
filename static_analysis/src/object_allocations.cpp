#include "object_allocations.h"

using namespace std;

queue<uint64_t> queue_vtable_addrs;
mutex queue_vtable_addrs_mtx;

ObjectAllocationFile::ObjectAllocationFile(const std::string &module_name)
    : _module_name(module_name){
}

void ObjectAllocationFile::export_object_allocations(
                                                const std::string &target_dir) {
    lock_guard<mutex> _(_mtx);

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << "_obj_allocs.txt";
    string target_file = temp_str.str();

    ofstream obj_alloc_file;
    obj_alloc_file.open(target_file);

    obj_alloc_file << _module_name << "\n";
    for(auto &kv : _obj_allocs) {
        obj_alloc_file << hex << kv.second.addr
                       << " ";
        for(uint64_t xref_addr : kv.second.vtbl_xref_addrs) {
            obj_alloc_file << hex << xref_addr
                           << " ";
        }
        obj_alloc_file << "\n";
    }

    obj_alloc_file.close();
}

const ObjectAllocationMap &ObjectAllocationFile::get_object_allocations() const {
    return _obj_allocs;
}

void ObjectAllocationFile::add_object_allocation(uint64_t vtable_init_addr,
                                                 uint32_t vtbl_idx,
                                                 uint64_t vtbl_xref_addr) {
    lock_guard<mutex> _(_mtx);

    if(_obj_allocs.find(vtable_init_addr) != _obj_allocs.end()) {
        _obj_allocs[vtable_init_addr].vtbl_idxs.insert(vtbl_idx);
        _obj_allocs[vtable_init_addr].vtbl_xref_addrs.insert(vtbl_xref_addr);
    }
    else {
        _obj_allocs[vtable_init_addr].addr = vtable_init_addr;
        _obj_allocs[vtable_init_addr].vtbl_idxs.insert(vtbl_idx);
        _obj_allocs[vtable_init_addr].vtbl_xref_addrs.insert(vtbl_xref_addr);
    }
}

/*!
 * \brief Check if the memory key is the correct one for the vtable pointer
 * init instruction.
 * \return True/False.
 */
inline bool check_correct_memory_key(const ExpressionPtr &index_reg_value_expr,
                                     const ExpressionPtr &offset_expr,
                                     const ExpressionPtr &mem_key) {

    // Check if the key contains our index register value.
    // For example:
    // mov [rax_1]#0 rdx_2
    // Value of index register rax: init_rax
    // Memory state of object: [init_rax] -> (0x600df0 + 0x0)
    // NOTE: This is just a fast heuristic for the memory object and
    // can yield false-positives (i.e., [init_rax + [init_rdi - 0x1]]
    // as memory object would also yield a positive result).
    if(mem_key->contains(*index_reg_value_expr)) {

        // If the memory object has also an offset like [init_rax + 0x10],
        // check if the same constant resides in the key object.
        // NOTE: This is just a heuristic and will still yield false-positives
        // for keys like [init_rax + [init_rdi - 0x54]] and the offset 0x54
        // is searched.
        Indirection &ind = static_cast<Indirection&>(*mem_key);
        Constant &offset = static_cast<Constant&>(*offset_expr);
        if(ind.address()->type() == ExpressionOperation
           && offset.value() != 0) {
            if(mem_key->contains(*offset_expr)) {
                return true;
            }
        }
        else {
            return true;
        }
    }
    return false;
}

/*!
 * \brief Symbollically execute created path in order to check if this is
 * a vtable pointer init instruction.
 * \return True/False.
 */
bool is_init_vtable_ptr_instr(const Translator &translator,
                              const VTable &vtable,
                              const BaseInstructionSSAPtrs &path,
                              Vex &vex) {

    // Since we only create basic blocks with one instruction and vex translates
    // the whole basic block, we do not want any optimization since we
    // can lose information otherwise (i.e., lea rdx [rip+0x10000], add rax, rdx
    // would only write the intermediate into rax).
    VexRegisterUpdates orig_iropt_register_updates_default =
                                       vex.get_iropt_register_updates_default();
    vex.set_iropt_register_updates_default(VexRegUpdAllregsAtEachInsn);

    // Create a path of artificial basic blocks with just
    // the instruction of our data flow path.
    const Memory &memory = translator.get_memory();
    vector<BlockPtr> exec_blocks;
    for(const BaseInstructionSSAPtr &instr : path) {

        // We are only interested in executing instructions.
        if(!instr->is_instruction()) {
            continue;
        }

        // Vex is not thread safe, so we have to lock this section.
        // NOTE: all attempts to make the Vex object thread safe
        // did not succeed.
        vex_mutex.lock();
        size_t real_end = 0;
        const IRSB &translated_block = vex.translate(
                                           memory[instr->get_address()],
                                           instr->get_address(),
                                           1,
                                           &real_end);
        IRSB *irsb_ptr = deepCopyIRSB_Heap(&translated_block);
        vex_mutex.unlock();

        // Our analysis skips call and ret instructions, therefore
        // we only have fallthrough terminators.
        Terminator terminator;
        terminator.type = TerminatorFallthrough;
        terminator.target = 0;
        terminator.fall_through = 0;
        BlockPtr block = make_shared<Block>(instr->get_address(),
                                            irsb_ptr,
                                            terminator,
                                            1);
        exec_blocks.push_back(block);
    }

    // Reset vex options.
    vex.set_iropt_register_updates_default(orig_iropt_register_updates_default);

    // Symbollically execute path.
    State state;
    for(uint32_t i = 0; i < exec_blocks.size(); i++) {
        const BlockPtr &block_ptr = exec_blocks.at(i);

        // Symbolically execute block.
        BlockSemantics semantics(*block_ptr, state);
        state = semantics.get_state();
    }

    const BaseInstructionSSAPtr &mov_instr = path.back();

#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
        cout << "Vtable pointer init instruction candidate: "
             << *mov_instr
             << endl;
#endif

    // Extract vex register of definition operand and constant.
    const OperandSSAPtr &def_op = mov_instr->get_definitions().at(0);
    shared_ptr<Register> index_reg_vex = nullptr;
    ExpressionPtr offset_expr = nullptr;
    switch(def_op->get_type()) {
        case SSAOpTypeMemoryX64: {
            const MemoryX64SSA &mem =
                             static_cast<const MemoryX64SSA &>(*def_op);
            const RegisterX64SSA &base_reg =mem.get_base();
            index_reg_vex = convert_ssa_reg_to_vex_reg(base_reg.get_index());

            // Convert offset into offset used by vex. SSA adds a negative value
            // while vex uses uint and a subtract operation for negative values.
            const ConstantX64SSA &offset = mem.get_offset();
            if(offset.get_value() < 0) {
                offset_expr = make_shared<Constant>(offset.get_value() * (-1));
            }
            else {
                offset_expr = make_shared<Constant>(offset.get_value());
            }
            break;
        }
        default:
            throw runtime_error("Unknown SSA memory object.");
    }

    // Get value of the memory index register.
    ExpressionPtr index_reg_value_expr = nullptr;
    State::const_iterator index_reg_value;
    if(state.find(index_reg_vex, index_reg_value)) {
        index_reg_value_expr = index_reg_value->second;
#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
        cout << "Vtable pointer init instruction index register value: "
             << *index_reg_value_expr
             << endl;
#endif
    }
    else {
#if DEBUG_OBJ_ALLOC_PRINT
        cerr << "No index register value found for "
             << "vtable pointer init instruction: "
             << *mov_instr
             << endl;
#endif
        return false;
    }

    const auto &state_mem = state.get_memory_accesses();
    for(const auto &kv_mem : state_mem) {
        const ExpressionPtr &mem_key = kv_mem.first;
        const ExpressionPtr &mem_value = kv_mem.second;

        // Vtable is written directly into memory object (normal case).
        // mov [rax], 0x1000
        if(mem_value->type() == ExpressionConstant) {

            Constant &vtable_addr = static_cast<Constant&>(*kv_mem.second);
            if(vtable_addr.value() != vtable.addr) {
                // Also allow the vtable to be shifted with 0x10. This handles
                // indirect vtable addressing like .bss. However,
                // this also allows abstract classes with the first two entries
                // 0 to be found (vtable search algorithm will falsely place
                // the beginning after the two 0 entries). We found that
                // these vtables are also placed into the object in mongod
                // either in the destructor or directly overwritten on the way.
                if((vtable_addr.value() + 0x10) != vtable.addr) {
                    continue;
                }
            }

#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
            cout << "Candidate memory state: "
                 << *mem_key
                 << " -> "
                 << *mem_value
                 << endl;
#endif

            if(check_correct_memory_key(index_reg_value_expr,
                                        offset_expr,
                                        mem_key)) {
#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
                cout << "Accepted memory state: "
                     << *mem_key
                     << " -> "
                     << *mem_value
                     << endl;
#endif
                return true;
            }
        }

        // Vtable is written indirectly into memory object.
        // Sometimes an add operation or an indirection for GOT vtables
        // are also present.
        else if(mem_value->type() == ExpressionOperation) {
            Operation &op = static_cast<Operation&>(*mem_value);

            // Only consider operations in the following form:
            // 0x1000 + 0
            // 0x1000 - 0
            // [GOT:0x1000] + 0x10
            if(op.operation() != OperationAdd
               && op.operation() != OperationSub) {
                continue;
            }
            if(op.rhs()->type() != ExpressionConstant) {
                continue;
            }

            // When we have a constant lhs only allow our vtable addr.
            if(op.lhs()->type() == ExpressionConstant) {
                Constant &vtable_addr = static_cast<Constant&>(*op.lhs());
                if(vtable_addr.value() != vtable.addr) {
                    // Also allow the vtable to be shifted with 0x10. This
                    // handles indirect vtable addressing like .bss. However,
                    // this also allows abstract classes with the first two
                    // entries 0 to be found (vtable search algorithm will
                    // falsely place the beginning after the two 0 entries).
                    // We found that these vtables are also placed into the
                    // object in mongod either in the destructor or directly
                    // overwritten on the way.
                    if((vtable_addr.value() + 0x10) != vtable.addr) {
                        continue;
                    }
                }
            }

            // An indirection as lhs is only allowed for GOT vtables.
            // Example: [GOT:0x1000] + 0x10
            else if(op.lhs()->type() == ExpressionIndirection){

                // Only consider vtables in GOT since we have
                // an indirection to the real vtable in this case.
                if(vtable.type != VTableTypeGot
                   && vtable.type != VTableTypeGotReloc) {
                    continue;
                }

                Indirection &ind = static_cast<Indirection&>(*op.lhs());
                if(ind.address()->type() != ExpressionConstant) {
                    continue;
                }

                Constant &vtable_addr = static_cast<Constant&>(*ind.address());
                if(vtable_addr.value() != vtable.addr) {
                    if(vtable_addr.value() != vtable.addr) {
                        // Also allow the vtable to be shifted with 0x10. This
                        // handles indirect vtable addressing like .bss.
                        // However, this also allows abstract classes with the
                        // first two entries 0 to be found (vtable search
                        // algorithm will falsely place the beginning after
                        // the two 0 entries). We found that these vtables are
                        // also placed into the object in mongod either in the
                        // destructor or directly overwritten on the way.
                        if((vtable_addr.value() + 0x10) != vtable.addr) {
                            continue;
                        }
                    }
                }
            }

            // Ignore all other cases.
            else {
                continue;
            }

            // Normal case.
            Constant &offset = static_cast<Constant&>(*op.rhs());
            if(offset.value() == 0) {
            }

            // Only allowed in GOT case because of the indirection.
            // Example: [GOT:0x1000] + 0x10
            // Example: [GOT:0x1000] + 0x68 (can happen if GOT or GOT reloc
            // is used and a sub-vtable is referenced)
            else if(vtable.type == VTableTypeGot
                    || vtable.type == VTableTypeGotReloc) {
            }

            // Ignore all other cases.
            else {
                continue;
            }

#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
            cout << "Candidate memory state: "
                 << *mem_key
                 << " -> "
                 << *mem_value
                 << endl;
#endif

            if(check_correct_memory_key(index_reg_value_expr,
                                        offset_expr,
                                        mem_key)) {
#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
                cout << "Accepted memory state: "
                     << *mem_key
                     << " -> "
                     << *mem_value
                     << endl;
#endif
                return true;
            }
        }
    }

    return false;
}

/*!
 * \brief Tracks data flow of start instruction forward until it is moved
 * into an memory object.
 * \return Returns BaseInstructionSSAPtrSet of the found instructions.
 */
BaseInstructionSSAPtrSet get_init_vtable_ptr_instr(
                                     const Translator &translator,
                                     const Function &func,
                                     const VTable &vtable,
                                     const BaseInstructionSSAPtr &start_instr,
                                     Vex &vex) {

    typedef pair<BaseInstructionSSAPtr, BaseInstructionSSAPtrs> QueueElement;

    // Search all instructions which are possible vtable pointer init
    // instructions starting from our vtable xref instruction.
    BaseInstructionSSAPtrSet init_vtbl_ptrs;

    OperandsSSAset seen;
    queue<QueueElement> work_queue;
    BaseInstructionSSAPtrs start_path;
    start_path.push_back(start_instr);
    work_queue.push(make_pair(start_instr, start_path));
    while(!work_queue.empty()) {

        QueueElement curr_element = work_queue.front();
        work_queue.pop();
        BaseInstructionSSAPtr &curr_instr = curr_element.first;
        BaseInstructionSSAPtrs &curr_path = curr_element.second;

        while(true) {

/*
// TODO / DEBUG
cout << *curr_instr << endl;
*/

            // Did we write the vtable pointer into a memory object?
            if(!curr_instr->get_definitions().empty()
               && curr_instr->get_definitions().at(0)->is_memory()
               && curr_instr->get_mnemonic() == "mov") { // TODO architecture specific

#if DEBUG_OBJ_ALLOC_PRINT_VERBOSE
                cout << "Curr Path: \n";
                for(auto &it : curr_path) {
                    cout << "-> " << *it << "\n";
                }
                cout << endl;
#endif

                // Symbollically execute path in order to check if the
                // vtable pointer is written into a memory object.
                if(is_init_vtable_ptr_instr(translator,
                                            vtable,
                                            curr_path,
                                            vex)) {
                    init_vtbl_ptrs.insert(curr_instr);
                }

                // Decide if memory resides on the stack.
                // NOTE: at the moment it is a simple check.
                // If rsp is used to reference the stack
                // or some other obscure way we will not find it.
                bool is_stack_memory = false;
                const OperandSSAPtr &op = curr_instr->get_definitions().at(0);
                switch(op->get_type()) {
                    case SSAOpTypeMemoryX64: {
                        const MemoryX64SSA &mem =
                                         static_cast<const MemoryX64SSA &>(*op);
                        const RegisterX64SSA &base_reg =mem.get_base();

                        // Check if base register is rbp and no index register
                        // is used.
                        if(base_reg.get_index() == 5
                           && !mem.has_index()) {

                            is_stack_memory = true;
                        }

                        break;
                    }
                    default:
                        throw runtime_error("Unknown SSA memory object.");
                }

                // Follow stack variable since we encountered cases
                // in which the stack variable is just used temporarily
                // and the vtable pointer is read from it at multiple
                // locations and then written into an object.
                // Happend when vtable pointer is read via .got in
                // mongod (mongod+vtv 0xeefbe3 for example).
                if(is_stack_memory) {
                    const BaseInstructionSSAPtrSet &use_instrs =
                                                 func.get_instrs_use_op_ssa(op);
                    for(const auto &it : use_instrs) {
                        BaseInstructionSSAPtrs temp_path = curr_path;
                        temp_path.push_back(it);
                        work_queue.push(make_pair(it, temp_path));
                    }
                }

                break;
            }

            // Find next instruction in which the vtable ptr is moved.
            else {

                // Instruction can have no definitions (i.e., ret instructions).
                if(curr_instr->get_definitions().empty()) {
                    break;
                }

                // Do not follow return values of calls (since we consider
                // vtable pointer init operation only intra-procedural).
                if(curr_instr->is_call()) {
                    break;
                }
                const OperandSSAPtr &op = curr_instr->get_definitions().at(0);

                // Handle loops.
                if(seen.find(op) != seen.end()) {
                    break;
                }
                seen.insert(op);

                const BaseInstructionSSAPtrSet &use_instrs =
                                                 func.get_instrs_use_op_ssa(op);
                if(use_instrs.empty()) {
                    break;
                }

                // In some edge cases a vtable pointer can move in different
                // ways into the object.
                else if(use_instrs.size() != 1) {
                    for(const auto &it : use_instrs) {

                        // Ignore instructions that have no definition
                        // like test rax_305 rax_305.
                        if(it->get_definitions().empty()) {
                            continue;
                        }

                        // Ignore instructions that have the operand we search
                        // also as definition like mov [rax_485]#10 rdx_183
                        // when we search for uses of rax_485.
                        // NOTE/TODO: Can we stop the search for this operand
                        // completely because it can not be a vtable pointer?
                        if(it->get_definitions().at(0)->contains(*op)) {
                            continue;
                        }

                        BaseInstructionSSAPtrs temp_path = curr_path;
                        temp_path.push_back(it);
                        work_queue.push(make_pair(it, temp_path));
                    }

                    break;
                }

                curr_instr = *use_instrs.begin();
                curr_path.push_back(curr_instr);
            }
        }
    }

    return init_vtbl_ptrs;
}

/*!
 * \brief Searches the instructions that moves the vtable pointer into the
 * object for the given vtable pointer xref address.
 * \return Returns a BaseInstructionSSAPtrSet of the found instructions.
 */
BaseInstructionSSAPtrSet get_init_vtable_ptr_instr(const Translator &translator,
                                                   const VTable &vtable,
                                                   Vex &vex,
                                                   uint64_t vtable_xref_addr) {

    const Function *temp_start_func = nullptr;
    try {
        temp_start_func = &translator.get_containing_function(
                                                  vtable_xref_addr);
    }
    catch(...) {
        cerr << "Function for vtable xref address "
             << hex << vtable_xref_addr
             << " not found. Skipping."
             << "\n";
        BaseInstructionSSAPtrSet empty_vtbl_ptrs;
        return empty_vtbl_ptrs;
    }
    const Function &func = *temp_start_func;

    // Find the correct instruction we want to trace forward
    // (since multiple instructions can have the same address like
    // multiple phi nodes).
    const BaseInstructionSSAPtrSet temp_instrs =
                             func.get_instruction_ssa(vtable_xref_addr,
                                                      SSAInstrTypeInstruction);
    const BaseInstructionSSAPtr *temp_instr_ptr = nullptr;
    for(const BaseInstructionSSAPtr &temp_instr : temp_instrs) {
        // If we were searching for a SSA instruction, we can only
        // get one back (otherwise the data ist corrupted).
        temp_instr_ptr = &temp_instr;
        break;
    }
    if(temp_instr_ptr == nullptr) {
        stringstream err_msg;
        err_msg << "Not able to find instruction with address "
                << hex << vtable_xref_addr
                << " for forward trace.";
        throw runtime_error(err_msg.str().c_str());
    }

    return get_init_vtable_ptr_instr(translator,
                                     func,
                                     vtable,
                                     *temp_instr_ptr,
                                     vex);
}

void object_allocation_analysis_thread(const string &module_name,
                                       const VTableFile &vtable_file,
                                       const Translator &translator,
                                       Vex &vex,
                                       ObjectAllocationFile &obj_alloc_file,
                                       uint32_t thread_number) {

    cout << "Starting object allocation analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;

    while(true) {

        // Get next vtable address that has to be analyzed.
        uint64_t vtable_addr;
        queue_vtable_addrs_mtx.lock();
        if(queue_vtable_addrs.empty()) {
            queue_vtable_addrs_mtx.unlock();
            break;
        }
        vtable_addr = queue_vtable_addrs.front();
        queue_vtable_addrs.pop();
        cout << "Analyzing vtable at address: "
             << hex << vtable_addr
             << ". Remaining vtables to analyze: "
             << dec << queue_vtable_addrs.size()
             << " (Thread: " << dec << thread_number << ")"
             << endl;
        queue_vtable_addrs_mtx.unlock();

        const VTable &vtable = vtable_file.get_vtable(module_name,
                                                      vtable_addr);

        for(uint64_t vtable_xref_addr : vtable.xrefs) {

            BaseInstructionSSAPtrSet vtable_init_instrs =
                                get_init_vtable_ptr_instr(translator,
                                                          vtable,
                                                          vex,
                                                          vtable_xref_addr);

            // Skip if we could not find any
            // vtable ptr init instruction.
            if(vtable_init_instrs.empty()) {
                continue;
            }

            for(const auto &vtable_init_instr: vtable_init_instrs) {

#if DEBUG_OBJ_ALLOC_PRINT
                cout << "Memory allocation instruction: "
                     << *vtable_init_instr
                     << " for vtable "
                     << hex << vtable.addr
                     << " at xref addr "
                     << hex << vtable_xref_addr
                     << "\n";
#endif

                obj_alloc_file.add_object_allocation(
                                               vtable_init_instr->get_address(),
                                               vtable.index,
                                               vtable_xref_addr);
            }
        }

        for(auto &kv_xref : vtable.indirect_xrefs) {
            for(uint64_t vtable_xref_addr : kv_xref.second) {

                BaseInstructionSSAPtrSet vtable_init_instrs =
                                get_init_vtable_ptr_instr(translator,
                                                          vtable,
                                                          vex,
                                                          vtable_xref_addr);

                // Skip if we could not find any
                // vtable ptr init instruction.
                if(vtable_init_instrs.empty()) {
                    continue;
                }

                for(const auto &vtable_init_instr: vtable_init_instrs) {

#if DEBUG_OBJ_ALLOC_PRINT
                    cout << "Memory allocation instruction: "
                         << *vtable_init_instr
                         << " for vtable "
                         << hex << vtable.addr
                         << " at xref addr "
                         << hex << vtable_xref_addr
                         << "\n";
#endif

                    obj_alloc_file.add_object_allocation(
                                               vtable_init_instr->get_address(),
                                               vtable.index,
                                               vtable_xref_addr);

                }
            }
        }
    }

    cout << "Finished object allocation analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;
}

void object_allocation_analysis(const string &module_name,
                                const VTableFile &vtable_file,
                                const Translator &translator,
                                Vex &vex,
                                ObjectAllocationFile &obj_alloc_file,
                                uint32_t num_threads) {

    // Set up queue with all vtable addresses that have to be analyzed.
    queue_vtable_addrs_mtx.lock();
    for(const auto &kv : vtable_file.get_vtables(module_name)) {
        const VTable &vtable = *kv.second;
        queue_vtable_addrs.push(vtable.addr);
    }
    queue_vtable_addrs_mtx.unlock();


// TODO / DEBUG
//num_threads = 1;


    // Analyze all vtable xrefs to find all vtable pointer init instructions.
    // For debugging purposes do not spawn any thread.
    if(num_threads == 1) {
        object_allocation_analysis_thread(module_name,
                                          vtable_file,
                                          translator,
                                          vex,
                                          obj_alloc_file,
                                          0);
    }
    else {
        thread *all_threads = new thread[num_threads];
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i] = thread(object_allocation_analysis_thread,
                                    module_name,
                                    ref(vtable_file),
                                    ref(translator),
                                    ref(vex),
                                    ref(obj_alloc_file),
                                    i);
        }
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i].join();
        }
        delete [] all_threads;
    }
}
