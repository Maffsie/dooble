FORMS           = UI/dooble.ui \
                  UI/dooble_about.ui \
                  UI/dooble_accepted_or_blocked_domains.ui \
                  UI/dooble_authenticate.ui \
                  UI/dooble_authentication_dialog.ui \
                  UI/dooble_certificate_exceptions.ui \
                  UI/dooble_certificate_exceptions_menu_widget.ui \
                  UI/dooble_certificate_exceptions_widget.ui \
                  UI/dooble_charts.ui \
                  UI/dooble_clear_items.ui \
		  UI/dooble_cookies_window.ui \
                  UI/dooble_downloads.ui \
                  UI/dooble_downloads_item.ui \
                  UI/dooble_favorites_popup.ui \
                  UI/dooble_floating_digital_clock.ui \
		  UI/dooble_history_window.ui \
                  UI/dooble_page.ui \
                  UI/dooble_popup_menu.ui \
                  UI/dooble_search_engines_popup.ui \
                  UI/dooble_settings.ui \
                  UI/dooble_style_sheet.ui

HEADERS		= Source/dooble.h \
                  Source/dooble_about.h \
                  Source/dooble_accepted_or_blocked_domains.h \
                  Source/dooble_address_widget.h \
                  Source/dooble_address_widget_completer.h \
                  Source/dooble_address_widget_completer_popup.h \
                  Source/dooble_application.h \
                  Source/dooble_certificate_exceptions.h \
                  Source/dooble_certificate_exceptions_menu_widget.h \
                  Source/dooble_charts.h \
                  Source/dooble_charts_file.h \
                  Source/dooble_charts_iodevice.h \
                  Source/dooble_charts_property_editor.h \
                  Source/dooble_charts_property_editor_xyseries.h \
                  Source/dooble_charts_xyseries.h \
                  Source/dooble_clear_items.h \
                  Source/dooble_cookies.h \
                  Source/dooble_cookies_window.h \
                  Source/dooble_cryptography.h \
                  Source/dooble_downloads.h \
                  Source/dooble_downloads_item.h \
                  Source/dooble_favorites_popup.h \
                  Source/dooble_gopher.h \
                  Source/dooble_history.h \
                  Source/dooble_history_table_widget.h \
                  Source/dooble_history_window.h \
                  Source/dooble_main_window.h \
                  Source/dooble_page.h \
                  Source/dooble_pbkdf2.h \
                  Source/dooble_popup_menu.h \
                  Source/dooble_search_engines_popup.h \
                  Source/dooble_search_widget.h \
                  Source/dooble_settings.h \
                  Source/dooble_style_sheet.h \
                  Source/dooble_swifty.h \
                  Source/dooble_tab_bar.h \
                  Source/dooble_tab_widget.h \
                  Source/dooble_table_view.h \
                  Source/dooble_tool_button.h \
                  Source/dooble_version.h \
		  Source/dooble_web_engine_url_request_interceptor.h \
                  Source/dooble_web_engine_page.h \
                  Source/dooble_web_engine_view.h

RESOURCES       += Documentation/documentation.qrc \
                   Icons/icons.qrc

SOURCES		= Source/dooble.cc \
                  Source/dooble_about.cc \
                  Source/dooble_accepted_or_blocked_domains.cc \
                  Source/dooble_address_widget.cc \
                  Source/dooble_address_widget_completer.cc \
                  Source/dooble_address_widget_completer_popup.cc \
                  Source/dooble_aes256.cc \
                  Source/dooble_application.cc \
                  Source/dooble_block_cipher.cc \
                  Source/dooble_certificate_exceptions.cc \
                  Source/dooble_certificate_exceptions_menu_widget.cc \
                  Source/dooble_charts.cc \
                  Source/dooble_charts_file.cc \
                  Source/dooble_charts_property_editor.cc \
                  Source/dooble_charts_property_editor_xyseries.cc \
                  Source/dooble_charts_xyseries.cc \
                  Source/dooble_clear_items.cc \
                  Source/dooble_cookies.cc \
                  Source/dooble_cookies_window.cc \
                  Source/dooble_cryptography.cc \
                  Source/dooble_database_utilities.cc \
                  Source/dooble_downloads.cc \
                  Source/dooble_downloads_item.cc \
                  Source/dooble_favicons.cc \
                  Source/dooble_favorites_popup.cc \
		  Source/dooble_gopher.cc \
                  Source/dooble_history.cc \
                  Source/dooble_history_table_widget.cc \
                  Source/dooble_history_window.cc \
                  Source/dooble_hmac.cc \
                  Source/dooble_main.cc \
                  Source/dooble_page.cc \
                  Source/dooble_pbkdf2.cc \
                  Source/dooble_popup_menu.cc \
                  Source/dooble_random.cc \
                  Source/dooble_search_engines_popup.cc \
                  Source/dooble_search_widget.cc \
                  Source/dooble_settings.cc \
                  Source/dooble_style_sheet.cc \
                  Source/dooble_tab_bar.cc \
                  Source/dooble_tab_widget.cc \
                  Source/dooble_table_view.cc \
                  Source/dooble_text_utilities.cc \
                  Source/dooble_threefish256.cc \
                  Source/dooble_tool_button.cc \
                  Source/dooble_ui_utilities.cc \
		  Source/dooble_web_engine_url_request_interceptor.cc \
                  Source/dooble_web_engine_page.cc \
                  Source/dooble_web_engine_view.cc

TRANSLATIONS    = Translations/dooble_Arab_BH_DZ_EG_IQ_JO_KW_LY_MA_OM_QA_SA_SY_YE.ts \
                  Translations/dooble_French_BE_BJ_BF_BI_FR_KM_CD_CI_DJ_DM_PF_TF_GA_GN_HT_LB_LU_ML_MR_YT_MC_NC_NE_NG_SN_TG_TN.ts \
                  Translations/dooble_Portuguese_AO_BR_CV_GW_MO_MZ_ST_TL.ts \
                  Translations/dooble_ae.ts \
                  Translations/dooble_af.ts \
                  Translations/dooble_al.ts \
                  Translations/dooble_al_sq.ts \
                  Translations/dooble_am.ts \
                  Translations/dooble_as.ts \
                  Translations/dooble_az.ts \
		  Translations/dooble_ast.ts \
                  Translations/dooble_bd_bn.ts \
                  Translations/dooble_be.ts \
                  Translations/dooble_bg.ts \
                  Translations/dooble_ca.ts \
                  Translations/dooble_crh.ts \
                  Translations/dooble_cz.ts \
                  Translations/dooble_de.ts \
		  Translations/dooble_de_DE.ts \
                  Translations/dooble_dk.ts \
                  Translations/dooble_ee.ts \
                  Translations/dooble_en.ts \
                  Translations/dooble_eo.ts \
                  Translations/dooble_es.ts \
                  Translations/dooble_et.ts \
                  Translations/dooble_eu.ts \
                  Translations/dooble_fi.ts \
                  Translations/dooble_fr.ts \
                  Translations/dooble_galician.ts \
                  Translations/dooble_gl.ts \
                  Translations/dooble_gr.ts \
                  Translations/dooble_hb.ts \
                  Translations/dooble_hi.ts \
                  Translations/dooble_hr.ts \
                  Translations/dooble_hu.ts \
                  Translations/dooble_ie.ts \
                  Translations/dooble_il.ts \
                  Translations/dooble_it.ts \
                  Translations/dooble_id.ts \
                  Translations/dooble_jp.ts \
                  Translations/dooble_kk.ts \
                  Translations/dooble_kn.ts \
                  Translations/dooble_ko.ts \
                  Translations/dooble_ku.ts \
                  Translations/dooble_ky.ts \
                  Translations/dooble_lk.ts \
                  Translations/dooble_lt.ts \
                  Translations/dooble_lv.ts \
                  Translations/dooble_ml.ts \
                  Translations/dooble_mk.ts \
                  Translations/dooble_mn.ts \
                  Translations/dooble_ms.ts \
                  Translations/dooble_mr.ts \
                  Translations/dooble_mt.ts \
                  Translations/dooble_nl.ts \
                  Translations/dooble_no.ts \
                  Translations/dooble_np.ts \
                  Translations/dooble_pa.ts \
                  Translations/dooble_pl.ts \
                  Translations/dooble_pl_PL.ts \
                  Translations/dooble_pt.ts \
                  Translations/dooble_pt_BR.ts \
                  Translations/dooble_ps.ts \
                  Translations/dooble_ro.ts \
                  Translations/dooble_ru.ts \
                  Translations/dooble_rw.ts \
                  Translations/dooble_se.ts \
                  Translations/dooble_sk.ts \
                  Translations/dooble_sl.ts \
                  Translations/dooble_sq.ts \
                  Translations/dooble_sr.ts \
                  Translations/dooble_sw.ts \
                  Translations/dooble_th.ts \
                  Translations/dooble_tr.ts \
                  Translations/dooble_vn.ts \
                  Translations/dooble_zh_CN_simple.ts \
                  Translations/dooble_zh_TW.ts \
                  Translations/dooble_zh_CN_traditional.ts
