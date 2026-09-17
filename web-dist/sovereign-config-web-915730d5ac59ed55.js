export function start() {
    wasm.start();
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_number_get_394265ed1e1b84ee: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_b0ca35b86a603356: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_fffb441def202758: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_activeElement_4bc99dc1a7094c27: function(arg0) {
            const ret = arg0.activeElement;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_addEventListener_d85450ee1320c989: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            arg0.addEventListener(getStringFromWasm0(arg1, arg2), arg3);
        }, arguments); },
        __wbg_appendChild_f553e8704c4f14a6: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.appendChild(arg1);
            return ret;
        }, arguments); },
        __wbg_append_01c74e5c6b58aa64: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.append(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_append_1e60bd927c609246: function(arg0, arg1, arg2, arg3, arg4) {
            arg0.append(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        },
        __wbg_arrayBuffer_3b637f0fa65c5351: function() { return handleError(function (arg0) {
            const ret = arg0.arrayBuffer();
            return ret;
        }, arguments); },
        __wbg_bottom_e6ed49b80d965dae: function(arg0) {
            const ret = arg0.bottom;
            return ret;
        },
        __wbg_checkValidity_3a31dcce278f31a1: function(arg0) {
            const ret = arg0.checkValidity();
            return ret;
        },
        __wbg_checkValidity_99c93eff5ece69a2: function(arg0) {
            const ret = arg0.checkValidity();
            return ret;
        },
        __wbg_checked_596d0d7b35f55a01: function(arg0) {
            const ret = arg0.checked;
            return ret;
        },
        __wbg_children_88145a67dc87f2ad: function(arg0) {
            const ret = arg0.children;
            return ret;
        },
        __wbg_clientX_a7dcb4081126cd4b: function(arg0) {
            const ret = arg0.clientX;
            return ret;
        },
        __wbg_clipboard_cc7335fcba1a9a80: function(arg0) {
            const ret = arg0.clipboard;
            return ret;
        },
        __wbg_close_b97b6a6385cfff98: function(arg0) {
            arg0.close();
        },
        __wbg_closest_d889c758da4bb13b: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.closest(getStringFromWasm0(arg1, arg2));
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_contains_7189b09a477442a6: function(arg0, arg1) {
            const ret = arg0.contains(arg1);
            return ret;
        },
        __wbg_createElementNS_013b3fb26f4796ec: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.createElementNS(arg1 === 0 ? undefined : getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            return ret;
        }, arguments); },
        __wbg_createElement_fcbc0805de826d62: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.createElement(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_crypto_29a13c24f21f7c72: function() { return handleError(function (arg0) {
            const ret = arg0.crypto;
            return ret;
        }, arguments); },
        __wbg_document_179650d6cb13c263: function(arg0) {
            const ret = arg0.document;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_fetch_6ecc661950e58d49: function(arg0, arg1) {
            const ret = arg0.fetch(arg1);
            return ret;
        },
        __wbg_focus_2f77051f98540625: function() { return handleError(function (arg0) {
            arg0.focus();
        }, arguments); },
        __wbg_from_13e323c65fc8f464: function(arg0) {
            const ret = Array.from(arg0);
            return ret;
        },
        __wbg_getAttribute_5a601ba4718b922a: function(arg0, arg1, arg2, arg3) {
            const ret = arg1.getAttribute(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_getBoundingClientRect_e828e6c31c66dea6: function(arg0) {
            const ret = arg0.getBoundingClientRect();
            return ret;
        },
        __wbg_getElementById_1cbd8f06dbe8eb8e: function(arg0, arg1, arg2) {
            const ret = arg0.getElementById(getStringFromWasm0(arg1, arg2));
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_getElementsByTagName_23bf451d70c31c13: function(arg0, arg1, arg2) {
            const ret = arg0.getElementsByTagName(getStringFromWasm0(arg1, arg2));
            return ret;
        },
        __wbg_getElementsByTagName_cefda492011ed883: function(arg0, arg1, arg2) {
            const ret = arg0.getElementsByTagName(getStringFromWasm0(arg1, arg2));
            return ret;
        },
        __wbg_getItem_b96269ddc16cf24a: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.getItem(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_getRandomValues_4d75c4f1f63e1972: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.getRandomValues(getArrayU8FromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_get_18e0163e38e5048d: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.get(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_get_78f252d074a84d0b: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_c0a83f5950240eca: function(arg0, arg1, arg2, arg3) {
            const ret = arg1.get(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_get_unchecked_6e0ad6d2a41b06f6: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_hasAttribute_1fc23d9b37b6dfb1: function(arg0, arg1, arg2) {
            const ret = arg0.hasAttribute(getStringFromWasm0(arg1, arg2));
            return ret;
        },
        __wbg_headers_cf9c80f30e2a4eff: function(arg0) {
            const ret = arg0.headers;
            return ret;
        },
        __wbg_history_e648b4314d9b256e: function() { return handleError(function (arg0) {
            const ret = arg0.history;
            return ret;
        }, arguments); },
        __wbg_href_bc4909da4ed58381: function(arg0, arg1) {
            const ret = arg1.href;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_id_2bb4f5057d3bfc99: function(arg0, arg1) {
            const ret = arg1.id;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_innerHeight_92315939e482496d: function() { return handleError(function (arg0) {
            const ret = arg0.innerHeight;
            return ret;
        }, arguments); },
        __wbg_instanceof_Element_beebfaab75d12d9d: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Element;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_HtmlButtonElement_2798f3f046c1c446: function(arg0) {
            let result;
            try {
                result = arg0 instanceof HTMLButtonElement;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_HtmlDialogElement_6e2866d7ca6d56d9: function(arg0) {
            let result;
            try {
                result = arg0 instanceof HTMLDialogElement;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_HtmlElement_4493a09212d3586f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof HTMLElement;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_HtmlInputElement_ad3be04339d0e4df: function(arg0) {
            let result;
            try {
                result = arg0 instanceof HTMLInputElement;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_HtmlTextAreaElement_37795f65e16b7ed0: function(arg0) {
            let result;
            try {
                result = arg0 instanceof HTMLTextAreaElement;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Response_c8b64b2256f01bec: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Response;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_05ba1ee4f6781663: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_item_80aedbc6650fb95e: function(arg0, arg1) {
            const ret = arg0.item(arg1 >>> 0);
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_json_77bd792f9a4a3fe1: function() { return handleError(function (arg0) {
            const ret = arg0.json();
            return ret;
        }, arguments); },
        __wbg_key_803dca86cdcfa8dd: function(arg0, arg1) {
            const ret = arg1.key;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_lastElementChild_8fcb396648ec04e2: function(arg0) {
            const ret = arg0.lastElementChild;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_left_7e76a74d0db1754f: function(arg0) {
            const ret = arg0.left;
            return ret;
        },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_370319915dc99107: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_dd6ada793074ef31: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_localStorage_5bf6ce3f8e51412a: function() { return handleError(function (arg0) {
            const ret = arg0.localStorage;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_location_c9a2271428996698: function(arg0) {
            const ret = arg0.location;
            return ret;
        },
        __wbg_navigator_99621db14b3f1099: function(arg0) {
            const ret = arg0.navigator;
            return ret;
        },
        __wbg_new_08cb2fa678b17a48: function() { return handleError(function (arg0, arg1) {
            const ret = new URL(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_0d809930cd1354c6: function() { return handleError(function () {
            const ret = new Headers();
            return ret;
        }, arguments); },
        __wbg_new_cc984128914cfc6f: function(arg0) {
            const ret = new Date(arg0);
            return ret;
        },
        __wbg_new_cd45aabdf6073e84: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_da52cf8fe3429cb2: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_f0787df90791d9ba: function() { return handleError(function () {
            const ret = new URLSearchParams();
            return ret;
        }, arguments); },
        __wbg_new_from_slice_77cdfb7977362f3c: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_with_str_454324b233393719: function() { return handleError(function (arg0, arg1) {
            const ret = new URLSearchParams(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_with_str_and_init_d95cbe11ce28e65e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new Request(getStringFromWasm0(arg0, arg1), arg2);
            return ret;
        }, arguments); },
        __wbg_now_86c0d4ba3fa605b8: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_ok_acc5e3fb89668864: function(arg0) {
            const ret = arg0.ok;
            return ret;
        },
        __wbg_origin_ed66c06e67ad2049: function() { return handleError(function (arg0, arg1) {
            const ret = arg1.origin;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_origin_fd7a89859af60f50: function(arg0, arg1) {
            const ret = arg1.origin;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_pathname_d27a358088ce7b2b: function() { return handleError(function (arg0, arg1) {
            const ret = arg1.pathname;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_pointerId_ea33d2695be12e7f: function(arg0) {
            const ret = arg0.pointerId;
            return ret;
        },
        __wbg_preventDefault_b64888c857500682: function(arg0) {
            arg0.preventDefault();
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_pushState_3d01701623122bc8: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
            arg0.pushState(arg1, getStringFromWasm0(arg2, arg3), arg4 === 0 ? undefined : getStringFromWasm0(arg4, arg5));
        }, arguments); },
        __wbg_queueMicrotask_0ab5b2d2393e99b9: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_6a09b7bc46549209: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_releasePointerCapture_3e982a4a25bf65a8: function() { return handleError(function (arg0, arg1) {
            arg0.releasePointerCapture(arg1);
        }, arguments); },
        __wbg_removeAttribute_1e7d2c409776d836: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.removeAttribute(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_removeItem_78e03a38da96e0ae: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.removeItem(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_remove_ce1b54059317fe8a: function(arg0) {
            arg0.remove();
        },
        __wbg_replaceState_9a0a4a53d3bf3439: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
            arg0.replaceState(arg1, getStringFromWasm0(arg2, arg3), arg4 === 0 ? undefined : getStringFromWasm0(arg4, arg5));
        }, arguments); },
        __wbg_resolve_2191a4dfe481c25b: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_scrollIntoView_8aebc47f4e6dd724: function(arg0, arg1) {
            arg0.scrollIntoView(arg1 !== 0);
        },
        __wbg_searchParams_23a839468a61ef4c: function(arg0) {
            const ret = arg0.searchParams;
            return ret;
        },
        __wbg_search_af2555aa41bd23cc: function() { return handleError(function (arg0, arg1) {
            const ret = arg1.search;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_sessionStorage_812615d3ac31fa09: function() { return handleError(function (arg0) {
            const ret = arg0.sessionStorage;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_setAttribute_71039043be82d098: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setAttribute(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_setCustomValidity_6a1d0ae59802ea4c: function(arg0, arg1, arg2) {
            arg0.setCustomValidity(getStringFromWasm0(arg1, arg2));
        },
        __wbg_setCustomValidity_caf00348e4c8a9d2: function(arg0, arg1, arg2) {
            arg0.setCustomValidity(getStringFromWasm0(arg1, arg2));
        },
        __wbg_setItem_364a11cf21db9039: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setItem(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_setPointerCapture_70025ca3fb7f26b9: function() { return handleError(function (arg0, arg1) {
            arg0.setPointerCapture(arg1);
        }, arguments); },
        __wbg_setProperty_e4e51b1b1d681d15: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setProperty(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_set_body_029f2d171e0a005f: function(arg0, arg1) {
            arg0.body = arg1;
        },
        __wbg_set_cache_b4a740b195c051f4: function(arg0, arg1) {
            arg0.cache = __wbindgen_enum_RequestCache[arg1];
        },
        __wbg_set_checked_ebff10552290d993: function(arg0, arg1) {
            arg0.checked = arg1 !== 0;
        },
        __wbg_set_className_e0b1e805ac9ecbf4: function(arg0, arg1, arg2) {
            arg0.className = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_disabled_7090948be77665bb: function(arg0, arg1) {
            arg0.disabled = arg1 !== 0;
        },
        __wbg_set_headers_9c61d123c3ee1f10: function(arg0, arg1) {
            arg0.headers = arg1;
        },
        __wbg_set_href_960e4284e5cae151: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.href = getStringFromWasm0(arg1, arg2);
        }, arguments); },
        __wbg_set_method_5532d59b92d76467: function(arg0, arg1, arg2) {
            arg0.method = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_textContent_54dcad83ae15772d: function(arg0, arg1, arg2) {
            arg0.textContent = arg1 === 0 ? undefined : getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_type_d2a9a3c584ce2f9a: function(arg0, arg1, arg2) {
            arg0.type = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_value_a342f135c825187d: function(arg0, arg1, arg2) {
            arg0.value = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_value_e5d078763e63e81e: function(arg0, arg1, arg2) {
            arg0.value = getStringFromWasm0(arg1, arg2);
        },
        __wbg_showModal_a752a06ee3bb248f: function() { return handleError(function (arg0) {
            arg0.showModal();
        }, arguments); },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_status_c45b3b9b3033184a: function(arg0) {
            const ret = arg0.status;
            return ret;
        },
        __wbg_style_6657aed849e5d757: function(arg0) {
            const ret = arg0.style;
            return ret;
        },
        __wbg_target_e759594a8d965ed7: function(arg0) {
            const ret = arg0.target;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_textContent_37277f66248f39e6: function(arg0, arg1) {
            const ret = arg1.textContent;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_then_16d107c451e9905d: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_6ec10ae38b3e92f7: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_toLocaleString_a215c3af6195af14: function(arg0, arg1, arg2, arg3) {
            const ret = arg0.toLocaleString(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        },
        __wbg_toString_b201c2690bbe445a: function(arg0) {
            const ret = arg0.toString();
            return ret;
        },
        __wbg_top_fe120acfa924a430: function(arg0) {
            const ret = arg0.top;
            return ret;
        },
        __wbg_type_c1987e7fbaf7340e: function(arg0, arg1) {
            const ret = arg1.type;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_value_1f687dfa7d6c3d08: function(arg0, arg1) {
            const ret = arg1.value;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_value_c40f8f7227bb3a9e: function(arg0, arg1) {
            const ret = arg1.value;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_writeText_34bfead2ae78e5bb: function(arg0, arg1, arg2) {
            const ret = arg0.writeText(getStringFromWasm0(arg1, arg2));
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 301, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___wasm_bindgen_85738b101f1a918f___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_85738b101f1a918f___JsError___true_);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("Event")], shim_idx: 213, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("KeyboardEvent")], shim_idx: 213, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true__2);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("PointerEvent")], shim_idx: 213, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true__3);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./sovereign-config-web_bg.js": import0,
    };
}

function wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true_(arg0, arg1, arg2);
}

function wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true__2(arg0, arg1, arg2) {
    wasm.wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true__2(arg0, arg1, arg2);
}

function wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true__3(arg0, arg1, arg2) {
    wasm.wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___web_sys_e7e9f5d32d6752c8___features__gen_PointerEvent__PointerEvent______true__3(arg0, arg1, arg2);
}

function wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___wasm_bindgen_85738b101f1a918f___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_85738b101f1a918f___JsError___true_(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_85738b101f1a918f___convert__closures_____invoke___wasm_bindgen_85738b101f1a918f___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_85738b101f1a918f___JsError___true_(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}


const __wbindgen_enum_RequestCache = ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"];

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('sovereign-config-web_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
