var wrlBandInfo;
var ajaxInterval;
var getDataTimer;
var lastMode;
var pageview = R.pageView({ //页面初始化
	init: initWrlBandPage
});

var G_data = {};
var pageModel = R.pageModel({
	getUrl: "goform/WifiRadioGet",
	setUrl: "goform/WifiRadioSet",
	translateData: function (data) {
		var newData = {};
		newData.wrlRadio = data;
		return newData;
	},
	afterSubmit: callback
});

/*************************************************************/

var view = R.moduleView({
	initEvent: function () {
		$("#adv_mode, #adv_mode_5g").on("change", getBandWidthList);

		$("#adv_band_5g").on("change", changeBandwidth);

		$("#warning,#warning_5g").on("click",function(){
			$("#warning-msg").removeClass("none");
			event.stopPropagation();
		});
		$(document).on("click",function(){
			$("#warning-msg").addClass("none");
		});
		
		$("#warning,#warning_5g").on("mouseover",function(){
			$("#warning-msg").removeClass("none");
		});
		$("#warning,#warning_5g").on("mouseleave",function(){
			$("#warning-msg").addClass("none");
		});
	}
});

var moduleModel = R.moduleModel({
	initData: initValue,
	getSubmitData: function () {
		return $("#wireless").serialize();
	}
});

//模块注册
R.module("wrlRadio", view, moduleModel);

function initWrlBandPage() {
	top.loginOut();
	top.$(".main-dailog").removeClass("none");
	top.$(".save-msg").addClass("none");
	$("#submit").on("click", function () {
		wrlBandInfo.submit();
	});

	getDataTimer = setTimeout(function () {
		ajaxInterval = new AjaxInterval({
			url: "goform/WifiRadioGet",
			successFun: setWrlCurrent,
			gapTime: 5000
		});
}, 5000);
}

function getBandWidthList() {
	var mode_5g = $("#adv_mode_5g").val(),
		bang_24g_init = $("#adv_band").val(),
		bang_5g_init = $("#adv_band_5g").val();

	$("#adv_band").val(bang_24g_init);
	if ($("#adv_band").val() != bang_24g_init) {
		$("#adv_band").val("20");
	}

  if ("160" in G_data.channel_5g && mode_5g != "an") {
		$("#adv_band_5g").html('<option value="20">20</option><option value="40">40</option><option value="80">80</option><option value="160">160</option><option value="auto">20/40/80/160</option>');
	} else if ("80" in G_data.channel_5g && mode_5g != "an") {
		$("#adv_band_5g").html('<option value="20">20</option><option value="40">40</option><option value="80">80</option><option value="auto">20/40/80</option>');
	} else if ("40" in G_data.channel_5g) {
		$("#adv_band_5g").html('<option value="20">20</option><option value="40">40</option><option value="auto">20/40</option>');
	} else {
		$("#adv_band_5g").html('<option value="20">20</option>').val("20");
	}

	if ($("#adv_band_5g option[value=" + bang_5g_init + "]").length == 0) {
		if ("80" in G_data.channel_5g) {
			$("#adv_band_5g").val(80);
		} else if ("40" in G_data.channel_5g) {
			$("#adv_band_5g").val(40);
		}
	} else {
		$("#adv_band_5g").val(bang_5g_init);
	}

	changeBandwidth();
}

function changeBandwidth() {

	var channel,
		channel_5g,
        len_5g,
        len,
		i = 0,
		bandwidth,
		bandwidth_5g,
		str = "",
		adv_channel = $("#adv_channel").val(),
		adv_channel_5g = $("#adv_channel_5g").val();


	bandwidth = $("#adv_band").val();
	channel = G_data.channel;
	len = channel.length;
	for (i = 0; i < len; i++) {
		if (i == 0) {
			str += "<option value='0'>" + _("Auto") + "</option>";
		} else {
			//str += "<option value='" + channel[i] + "'>" + _("Channel") + " " + channel[i] + "</option>";
			str += "<option value='" + channel[i] + "'>" + _("Channel") + " " + channel[i] + "</option>";
		}
	}
	$("#adv_channel").html(str);

	if ($("#adv_mode").val() == "b") {
		$("#adv_band").val("20");
		$("#adv_band option[value='40']").addClass("none");
		$("#adv_band option[value='auto']").addClass("none");
	} else {
		$("#adv_channel option[value='14']").addClass("none");
		$("#adv_band option[value='40']").removeClass("none");
		$("#adv_band option[value='auto']").removeClass("none");
		lastMode == "b" && $("#adv_band").val("auto");
	}


	if ($("#adv_channel option[value=" + adv_channel + "]").length == 0) {
		$("#adv_channel").val(0);
	} else {
		$("#adv_channel").val(adv_channel);
	}

	if (lastMode == "b" && $("#adv_mode").val() !== "b" && adv_channel == "14"){
		$("#adv_channel").val(0);
	}

	if ($("#adv_mode").val() == "bgn+ac+ax") {
    $("#warning").removeClass("none");
  } else {
    $("#warning").addClass("none");
  }

	str = "";
	bandwidth_5g = $("#adv_band_5g").val();
	if (bandwidth_5g == "auto") {
		if ("80" in G_data.channel_5g) {
			bandwidth_5g = "80";
		} else {
			bandwidth_5g = "40";
		}
	}

	bandwidth_5g = (bandwidth_5g == "auto" ? "80" : bandwidth_5g);
	channel_5g = G_data.channel_5g[bandwidth_5g];
	len_5g = channel_5g.length;
	for (i = 0; i < len_5g; i++) {
		if (i == 0) {
			str += "<option value='0'>" + _("Auto") + "</option>";
		} else {
			//str += "<option value='" + channel_5g[i] + "'>" + _("Channel") + " " + channel_5g[i] + "</option>";
			str += "<option value='" + channel_5g[i] + "'>" + _("Channel") + " " + channel_5g[i] + "</option>";
		}
	}
	$("#adv_channel_5g").html(str);
	if ($("#adv_channel_5g option[value=" + adv_channel_5g + "]").length == 0) {
		$("#adv_channel_5g").val("0");
	} else {
		$("#adv_channel_5g").val(adv_channel_5g);
	}

	
	if ($("#adv_mode_5g").val() == "an+ac+ax") {
    $("#warning_5g").removeClass("none");
  } else {
    $("#warning_5g").addClass("none");
	}
	
	lastMode = $("#adv_mode").val();
}

function initValue(obj) {
	var bandWidth_5g;
	G_data = obj;
	lastMode = obj.adv_mode;

	top.$(".main-dailog").removeClass("none");
	top.$("iframe").removeClass("none");
	top.$(".loadding-page").addClass("none");
	
	if (obj.adv_country == "JP") {
		$("#adv_mode option[value='b']").removeClass("none");
	}
	//inputValue(obj);
	$("#adv_mode").val(obj.adv_mode);
	$("#adv_mode_5g").val(obj.adv_mode_5g);
	getBandWidthList();

	$("#adv_band").val(obj.adv_band);
	$("#adv_band_5g").val(obj.adv_band_5g);

	changeBandwidth();
	$("#adv_channel").val(obj.adv_channel);
	$("#adv_channel_5g").val(obj.adv_channel_5g);
	getBandWidthList();

	setWrlCurrent(obj);
}

function setWrlCurrent(obj) {
	//该数据不是必传的
	$("#adv_current_band").html((obj.adv_current_band || G_data.adv_current_band) + "MHz");
	$("#adv_current_channel").html((obj.adv_current_channel || G_data.adv_current_channel));
	$("#adv_current_band_5g").html((obj.adv_current_band_5g || G_data.adv_current_band_5g) + "MHz");
	$("#adv_current_channel_5g").html(obj.adv_current_channel_5g || G_data.adv_current_channel_5g);
}

//执行回调
function callback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	top.showSaveMsg(num);
	if (num == "0") {
		top.wrlInfo.initValue();
		window.clearTimeout(getDataTimer);
		ajaxInterval && ajaxInterval.stopUpdate();
	}
}

/***************************************************************/


window.onload = function () {
	wrlBandInfo = R.page(pageview, pageModel);
};