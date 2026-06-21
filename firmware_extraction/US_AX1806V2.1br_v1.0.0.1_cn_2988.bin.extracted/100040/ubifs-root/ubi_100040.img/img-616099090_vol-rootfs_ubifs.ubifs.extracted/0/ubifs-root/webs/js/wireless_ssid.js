/**************** Page *******************************/
var wrlBasicPage;
var storageSSID24,storageSSID24En;
var noencryption = "Wi-Fi不加密，有被人蹭网的风险，建议设置Wi-Fi加密。"
var wpa3sae = "请确认接入终端支持WPA3-SAE模式。使用中如遇到设备连接问题，建议切回WPA2-PSK。"
var wpa3saewpa2psk = "请确认接入终端支持WPA3-SAE/WPA2-PSK混合模式。使用中如遇到设备连接问题，建议切回WPA2-PSK。"
var G = {};
var pageview = R.pageView({ //页面初始化
	init: initPage
}); //page view

//page model
var pageModel = R.pageModel({
	getUrl: "goform/WifiBasicGet", //获取数据接口
	setUrl: "goform/WifiBasicSet", //提交数据接口
	translateData: function (data) { //数据转换
		var newData = {};
		newData.wrlBasic = data;
		return newData;
	},
	afterSubmit: function (str) { //提交数据回调
		callback(str);
	}
});

//页面逻辑初始化
function initPage() {
	$.validate.valid.ssid = {
		all: function (str) {
			var ret = this.specific(str);
			//ssid 前后不能有空格，可以输入任何字符包括中文，仅32个字节的长度
			if (ret) {
				return ret;
			}

			/*if (str.charAt(0) == " " || str.charAt(str.length - 1) == " ") {
				return _("The first and last characters of WiFi Name cannot be spaces.");
			}*/

			if (getStrByteNum(str) > 32) {
				return _("The WiFi name can contain only a maximum of %s bytes.", [32]);
			}
		},
		specific: function (str) {
			var ret = str;
			if ((null == str.match(/[^ -~]/g) ? str.length : str.length + str.match(/[^ -~]/g).length * 2) > 32) {
				return _("The WiFi name can contain only a maximum of %s bytes.", [32]);
			}
		}
	};
	$.validate.valid.ssidPwd = {
		all: function (str) {
			var ret = this.specific(str);

			if (ret) {
				return ret;
			}
			if ((/^[0-9a-fA-F]{1,}$/).test(str) && str.length == 64) { //全是16进制 且长度是64

			} else {
				if (str.length < 8 || str.length > 63) {
					return _("The password must consist of %s-%s characters.", [8, 63]);
				}
			}
			//密码不允许输入空格
			//if (str.indexOf(" ") >= 0) {
			//	return _("The WiFi password cannot contain spaces.");
			//}
			//密码前后不能有空格
			/*if (str.charAt(0) == " " || str.charAt(str.length - 1) == " ") {
				return _("The first and last characters of WiFi Password cannot be spaces.");
			}*/
		},
		specific: function (str) {
			var ret = str;
			if (/[^\x00-\x80]/.test(str)) {
				return _("Invalid characters are not allowed.");
			}
		}
	};

	$("#save").on("click", function () {
		G.validate.checkAll();
	});
	$('#hide_ssid,#hide_ssid_5g').on("click",function (){
		if(G.meshEn==="1"){
			alert('启用此功能，需先关闭“MESH组网”')
		}
	})
}

//提交回调
function callback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	top.showSaveMsg(num);
	if (num == 0) {
		$("#wrl_submit").blur();
		top.wrlInfo.initValue();
		top.staInfo.initValue();
	}
}

/****************** Page end ********************/

/****************** Module wireless setting *****/

var view = R.moduleView({
	initHtml: initHtml,
	initEvent: initEvent
});

var moduleModel = R.moduleModel({
	initData: initValue,
	getSubmitData: function () { //获取模块提交数据

		getCheckbox(["hideSsid", "hideSsid_5g"]);

		var dataObj = {
				"doubleBand":$("#doubleBandEn").attr("class").indexOf("btn-off") == -1 ? "1":"0",
				"wrlEn": $('[name="wrlEn"]').val(),
				"wrlEn_5g": $('[name="wrlEn_5g"]').val(),
				"wrlEn_wifi5": $('#wrlEn_wifi5').val(),
				"security": $("#security").val(),
				"security_5g": $("#security_5g").val(),
				"ssid": $("#ssid").val(),
				"ssid_5g": $("#ssid_5g").val(),
				"hideSsid": $("#hideSsid").val(),
				"hideSsid_5g": $("#hideSsid_5g").val(),
				"wrlPwd": $("#wrlPwd").val(),
				"wrlPwd_5g": $("#wrlPwd_5g").val()
			},
			dataStr;
			if(dataObj.doubleBand == "1"){  //双频优选开启时  5g信息保持和24g一样
				for(prop in dataObj){
					if(prop.indexOf("_5g")){
						dataObj[prop] = dataObj[prop.replace(/_5g/,"")];
					}
				}
			}


		dataStr = objTostring(dataObj);
		return dataStr;
	}
});
//模块注册
R.module("wrlBasic", view, moduleModel);

//初始化页面
function initHtml() {
	top.$(".main-dailog").removeClass("none");
	top.$(".save-msg").addClass("none");
}

//事件初始化
function initEvent() {
	$('[name^="wrlEn"], [name^="wrlEn_5g"],[name="wrlEn_wifi5"]').on("click", function () {
		var setVal = $(this).hasClass("btn-off") ? 1: 0;
		var _name = $(this).attr("name");
		changeWireEn(_name, setVal);
	});

	$("#doubleBandEn").on("click",changeDoubleBand);

	$("select").on("change", function () {
		if ($(this).val() === "none") {
			$(this).parent().parent().next().find("input").val("").attr("disabled", true);
			$(this).parent().parent().next().find("input").removeValidateTip(true).removeClass("validatebox-invalid");
			$(this).siblings("span").html(noencryption)
		} else {
			$(this).parent().parent().next().find("input").attr("disabled", false);
			switch ($(this).val()) {
				case "wpa3sae":
					$(this).siblings("span").html(wpa3sae)
					break;
				case "wpa3saewpa2psk":
					$(this).siblings("span").html(wpa3saewpa2psk)
					break;
				default:
					$(this).siblings("span").html("");
			}
		}
	});

	top.loginOut();
	checkData();
}
// function changeSecurity
//模块数据验证
function checkData() {
	G.validate = $.validate({
		custom: function () {
			//if ($("#wrlEn").hasClass("btn-on")) {
			if (($("#security").val() !== "none") && ($("#wrlPwd").val() === "")) {
				return _("Please specify your 2.4 GHz WiFi password.");
			}
			//}

			//if ($("#wrlEn_5g").hasClass("btn-on")) {
			if (($("#security_5g").val() !== "none") && ($("#wrlPwd_5g").val() === "")) {
				return _("Please specify your 5 GHz WiFi password.");
			}
			//}

			// WiFi 5 备用网络开启，需要判断无线名称长度
			var wrlEn_wifi5 = $('[name="wrlEn_wifi5"]').val();
			
			if (wrlEn_wifi5 === '1') {
				// 获取2.4G ssid， 5G ssid
				// 如果是双频合一关闭，则获取2.4G开关，5G开关
				// 如果双频合一开启，则只需要获取2.4Gssid
				// 备用wifi会在对应频段上面添加-wifi5 6个字符，因此对应频段的ssid只能是32 - 6，即26个
				var ssid24G = $('#ssid').val();
				var ssid5G = $('#ssid_5g').val();
				var ssidEn24G = $('[name="wrlEn"]').val();
				var ssidEn5G = $('[name="wrlEn_5g"]').val();


				var doubleEn = $("#doubleBandEn").attr("class").indexOf("btn-off") == -1 ? "1":"0";

			

				if (ssidEn24G === '1') {
					if (getStrByteNum(ssid24G) > 25) {
						if (doubleEn === '0') {
							return '当前2.4G网络无线名称会导致备用网络无线名称超过32位，请修改2.4G网络无线名称';
						} else {
							return '当前无线名称会导致备用网络无线名称超过32位，请修改无线名称';	
						}
						
					}
				}

				if (doubleEn === '0' && ssidEn5G === '1') {
					// 双频合一关闭，还要判断5G
					if (getStrByteNum(ssid5G) > 25) {
						return '当前5G网络无线名称会导致对应备用网络5G无线名称超过32位，请修改5G网络无线名称';
					}
				}


			}
		},

		success: function () {
			wrlBasicPage.submit();
		},

		error: function (msg) {
			if (msg) {
				$("#wrl_save_msg").html(msg);
				setTimeout(function () {
					$("#wrl_save_msg").html("&nbsp;");
				}, 3000);
			}
			return;
		}
	});
}
function initDoubleBand(en){
	var $ssid2Elem = $('[name="wrlEn"]');
	if(en == "0"){//双频合一关闭时   正常显示配置
		$("#doubleBandEn").removeClass("btn-on").addClass("btn-off");
		$("#5g_fieldset").removeClass("none");
	}else{//双频优选合一时，只显示2.4G
		$("#doubleBandEn").removeClass("btn-off").addClass("btn-on");
		$("#5g_fieldset").addClass("none");
		$("#ssidText").html(_("Enable WiFi Network")); //TODO
		$("#wifi-5-text").html("2.4G无线名称：");
	//	$("#ssid_5g").val(storageSSID24 + "_5G");

		//2.4G开关
		if (storageSSID24En === "0") {
			$ssid2Elem.attr("class", "btn-off").val(0);
			$ssid2Elem.parent().parent().nextAll().addClass("none").val(1);
		} else {
			$ssid2Elem.attr("class", "btn-on");
			$ssid2Elem.parent().parent().nextAll().removeClass("none");
		}
	}
}

function changeDoubleBand(){
	var enabled = $("#doubleBandEn").attr("class").indexOf("btn-off");
	var ssidVal = $("#ssid").val();
	if(enabled == -1){//开启 => 关闭
		$("#doubleBandEn").removeClass("btn-on").addClass("btn-off");
		$("#doubleBandEn").val(0);
		$("#5g_fieldset").removeClass("none");
		$("#ssidText").html(_("2.4 GHz Network"));
		$("#wifi-5-text").html("2.4G无线名称：");
		$("#ssid").val(ssidVal);

		//ssid中有2.4G时，替换为5G
		if(/(2\.4G)/ig.test(ssidVal)) {
				$("#ssid_5g").val(ssidVal.replace(/(2\.4[G|g])/g, "5G"));
		} else {
			//否则后面直接加-5G
			$("#ssid_5g").val(ssidVal.slice(0,29) + "-5G");
		}

		//切换时默认开启无线开关
		changeWireEn("wrlEn", 1);
		changeWireEn("wrlEn_5g", 1);
		changeWireEn("wrlEn_wifi5", 0);

		//同步加密方式和密码
		$("#security_5g").val($("#security").val());
		//去掉错误信息
		$("#wrlPwd_5g").val($("#wrlPwd").val()).removeValidateTip(true).removeClass("validatebox-invalid");;
		$("#security_5g").trigger("change");


	}else{//关闭 =》开启
		//2.4G一定开启
		$("#doubleBandEn").removeClass("btn-off").addClass("btn-on");
		$("#doubleBandEn").val(1);
		$("#5g_fieldset").addClass("none");
		$("#ssidText").html(_("Enable WiFi Network"));
		$("#wifi-5-text").html("无线名称：");
		//storageSSID24 = $("#ssid").val();
		//$("#ssid").val(storageSSID24.slice(0,storageSSID24.length).replace(/-2.4[g|G]/g,"").replace(/_2.4[g|G]/g,""));
		//切换时默认开启无线开关
		changeWireEn("wrlEn", 1);
		changeWireEn("wrlEn_wifi5", 0);
	}
}

//设置
function changeWireEn(_name, setVal) {
	var $elem = $("[name=" +_name+ "]");
	$elem.attr("class", setVal === 1 ? "btn-on": "btn-off").val(setVal);

	if (setVal === 1) {
		$elem.parent().parent().nextAll().removeClass("none");
	} else {
		$elem.parent().parent().nextAll().addClass("none");
	}
	top.initIframeHeight();
	changeBackupSSID();
}

function changeBackupSSID(){
		// 双频合一时 2.4G 关闭 即关闭
		// 非双频合一时 2.4G和5G都关闭的时候 为关闭
		// 
		var doubleBandEn = $("#doubleBandEn").hasClass("btn-on");
		var wrlEn = $("#wrlEn").hasClass("btn-on");
		var wrlEn_5g = $("#wrlEn_5g").hasClass("btn-on");

		if((doubleBandEn && !wrlEn) || (!wrlEn && !wrlEn_5g)){
			//隐藏 并关闭
			$("#5g_wifi").addClass("none");
			initEn($('#wrlEn_wifi5'), "off");
		}else{
			$("#5g_wifi").removeClass("none");
		}

		// 关闭时不显示对应的备用ssid
		if(wrlEn){
			$("#ssid_wifi5").parents(".control-group").removeClass("none");
		}else{
			$("#ssid_wifi5").parents(".control-group").addClass("none");
		}

		// 双频合一时不显示
		if(wrlEn_5g && !doubleBandEn){
			$("#ssid_wifi5_5g").parents(".control-group").removeClass("none")
		}else{
			$("#ssid_wifi5_5g").parents(".control-group").addClass("none")
		}
}

function initEn(ele, en) {
	if (en === "on") {
		ele.attr("class", "btn-on");
		ele.val(1);
		ele.parent().parent().nextAll().removeClass("none");
	} else {
		ele.attr("class", "btn-off");
		ele.val(0);
		ele.parent().parent().nextAll().addClass("none");
	}
}

function initValue(obj) {
	inputValue(obj);
	if (obj.wrlEn === "1") {
		initEn($('[name="wrlEn"]'), "on");
	} else {
		initEn($('[name="wrlEn"]'), "off");
	}

	if (obj.wrlEn_5g === "1") {
		initEn($('[name="wrlEn_5g"]'), "on");
	} else {
		initEn($('[name="wrlEn_5g"]'), "off");
	}

	if (obj.wrlEn_wifi5 === "1") {
		initEn($('#wrlEn_wifi5'), "on");
	} else {
		initEn($('#wrlEn_wifi5'), "off");
	}
	storageSSID24 = obj.ssid;
	storageSSID24En = obj.wrlEn;
	initDoubleBand(obj.doubleBand);
	changeBackupSSID();
	$("#ssid_wifi5").text(obj.ssid_wifi5);
	$("#ssid_wifi5_5g").text(obj.ssid_wifi5_5g);

	$("#wrlPwd").initPassword("", false, false);
	$("#wrlPwd_5g").initPassword("", false, false);

	//mainPageLogic.validate.checkAll("wrl-form");
	if (obj.security === "none") {
		$("#wrlPwd").val("").attr("disabled", true);
		$("#securityTip").html(noencryption)
		if ($("#wrlPwd_").length > 0) {
			$("#wrlPwd_").val("").attr("disabled", true);
		}
	} else {
		$("#wrlPwd").attr("disabled", false);
		switch (obj.security) {
			case "wpa3sae":
				$("#securityTip").html(wpa3sae)
				break;
			case "wpa3saewpa2psk":
				$("#securityTip").html(wpa3saewpa2psk)
				break;
			default:
				$("#securityTip").html("");
		}
		if ($("#wrlPwd_").length > 0) {
			$("#wrlPwd_").attr("disabled", false);
		}
	}

	if (obj.security_5g === "none") {
		$("#wrlPwd_5g").val("").attr("disabled", true);
		$("#securityTip_5g").html(noencryption);
		if ($("#wrlPwd_5g_").length > 0) {
			$("#wrlPwd_5g_").val("").attr("disabled", true);
		}
	} else {
		$("#wrlPwd_5g").attr("disabled", false);
		switch (obj.security_5g) {
			case "wpa3sae":
				$("#securityTip_5g").html(wpa3sae)
				break;
			case "wpa3saewpa2psk":
				$("#securityTip_5g").html(wpa3saewpa2psk)
				break;
			default:
				$("#securityTip_5g").html("");
		}

		if ($("#wrlPwd_5g_").length > 0) {
			$("#wrlPwd_5g_").attr("disabled", false);
		}
	}
	//mesh模式下固定为WPA2，且不可修改
	if (top.wrlInfo.data.meshEn === "1") {
		$("#security, #security_5g").val("wpa2psk").prop("disabled", "disabled");
		$("#wrlPwd, #wrlPwd_5g").attr("disabled", false);
	}

	if (obj.hideSsid == "1") {
		$("#hideSsid")[0].checked = true;
	} else {
		$("#hideSsid")[0].checked = false;
	}
	if (obj.hideSsid_5g == "1") {
		$("#hideSsid_5g")[0].checked = true;
	} else {
		$("#hideSsid_5g")[0].checked = false;
	}
	$.getJSON("goform/GetMeshCfg?" + Math.random(), function (obj){
	G.meshEn=obj.meshEn
	if(G.meshEn === "1"){
		$("#hideSsid_5g").attr('disabled',true)
		$("#hideSsid").attr('disabled',true)
	}
	});
}

/******************* Module wireless setting end ************/

window.onload = function () {
	wrlBasicPage = R.page(pageview, pageModel);
};