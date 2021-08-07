<?php
/* Copyright 2008-2016  Kyle Baker  (email: kyleabaker@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

// Security measure
defined( 'ABSPATH' ) or die( 'Cannot access pages directly.' );

// Detect Web Browsers
function wpua_detect_webbrowser()
{
	global $useragent, $wpua_show_version;

	$version = null;

	if (preg_match('/360se/i', $useragent))
	{
		$link = 'http://se.360.cn/';
		$title = '360 Safety Browser';
		$version = '';
		$code = '360se';
	}
	elseif (preg_match('/360ee/i', $useragent))
	{
		$link = 'http://chrome.360.cn/';
		$title = '360 Speed Browser';
		$version = '';
		$code = '360ee';
	}
	elseif (preg_match('/MRCHROME/i', $useragent))
	{
		$link = 'http://amigo.mail.ru/';
		$title = 'Amigo';
		$version = '';
		$code = 'amigo';
	}
	elseif (preg_match('/Arora/i', $useragent))
	{
		$link = 'http://code.google.com/p/arora/';
		$title = 'Arora';
		$code = 'arora';
	}
	elseif (preg_match('/Avant\ Browser/i', $useragent))
	{
		$link = 'http://www.avantbrowser.com/';
		$title = 'Avant Browser';
		$version = wpua_detect_browser_version('Browser');
		$code = 'avantbrowser';
	}
	elseif (preg_match('/WhiteHat\ Aviator/i', $useragent))
	{
		$link = 'http://www.whitehatsec.com/aviator/';
		$title = 'Aviator';
		$code = 'aviator';
	}
	elseif (preg_match('/baidubrowser/i', $useragent))
	{
		$link = 'http://liulanqi.baidu.com/';
		$title = 'Baidu Browser';
		$version = wpua_detect_browser_version('Browser');
		$code = 'baidubrowser';
	}
	elseif (preg_match('/\ Spark/i', $useragent))
	{
		$link = 'http://en.browser.baidu.com/';
		$title = 'Baidu Spark';
		$version = wpua_detect_browser_version('Spark');
		$code = 'baiduspark';
	}
	elseif (preg_match('/BlackHawk/i', $useragent))
	{
		$link = 'http://www.netgate.sk/blackhawk/help/welcome-to-blackhawk-web-browser.html';
		$title = 'BlackHawk';
		$code = 'blackhawk';
	}
	elseif (preg_match('/Bolt/i', $useragent))
	{
		$link = 'http://en.wikipedia.org/wiki/Bolt_(web_browser)';
		$title = 'Bolt';
		$code = 'bolt';
	}
	elseif (preg_match('/Iron/i', $useragent))
	{
		$link = 'http://www.srware.net/en/software_srware_iron.php';
		$title = 'SRWare Iron';
		$version = wpua_detect_browser_version('Iron');
		$code = 'srwareiron';
	}
	elseif (preg_match('/Chromium/i', $useragent))
	{
		$link = 'http://www.chromium.org/';
		$title = 'Chromium';
		$code = 'chromium';
	}
	elseif (preg_match('/coc_coc_browser/i', $useragent))
	{
		$link = 'http://coccoc.vn/';
		$title = 'Coc Coc';
		$version = wpua_detect_browser_version('coc_coc_browser');
		$code = 'coccoc';
	}
	elseif (preg_match('/Comodo_Dragon/i', $useragent))
	{
		$link = 'http://www.comodo.com/home/internet-security/browser.php';
		$title = 'Comodo Dragon';
		$version = wpua_detect_browser_version('Dragon');
		$code = 'comodo-dragon';
	}
	elseif (preg_match('/Chrome/i', $useragent)
		&& preg_match('/Cent\//i', $useragent))
	{
		$link = 'http://www.centbrowser.com';
		$title = 'Cent Browser';
		$version = wpua_detect_browser_version('Cent\/');
		$code = 'centbrowser';
	}
	elseif (preg_match('/CrMo/i', $useragent))
	{
		$link = 'http://www.google.com/chrome';
		$title = 'Chrome Mobile';
		$version = wpua_detect_browser_version('CrMo');
		$code = 'chrome';
	}
	elseif (preg_match('/CriOS/i', $useragent))
	{
		$link = 'http://www.google.com/chrome';
		$title = 'Chrome';
		$version = wpua_detect_browser_version('CriOS');
		$code = 'chrome';
	}
	elseif (preg_match('/Dillo/i', $useragent))
	{
		$link = 'http://www.dillo.org/';
		$title = 'Dillo';
		$code = 'dillo';
	}
	elseif (preg_match('/Dolfin/i', $useragent))
	{
		$link = 'http://www.samsungmobile.com/';
		$title = 'Dolfin';
		$code = 'samsung';
	}
	elseif (preg_match('/Dooble/i', $useragent))
	{
		$link = 'http://textbrowser.github.io/dooble/';
		$title = 'Dooble';
		$code = 'dooble';
	}
	elseif (preg_match('/Edbrowse/i', $useragent))
	{
		$link = 'http://edbrowse.org/';
		$title = 'Edbrowse';
		$code = 'edbrowse';
	}
	elseif (preg_match('/Epic/i', $useragent))
	{
		$link = 'http://www.epicbrowser.com/';
		$title = 'Epic';
		$code = 'epicbrowser';
	}
	elseif (preg_match('/Epiphany/i', $useragent))
	{
		$link = 'http://gnome.org/projects/epiphany/';
		$title = 'Epiphany';
		$code = 'epiphany';
	}
	elseif (preg_match('/Fennec/i', $useragent))
	{
		$link = 'https://wiki.mozilla.org/Fennec';
		$title = 'Fennec';
		$code = 'fennec';
	}
	elseif (preg_match('/Firebird/i', $useragent))
	{
		$link = 'http://seb.mozdev.org/firebird/';
		$title = 'Firebird';
		$code = 'firebird';
	}
	elseif (preg_match('/Fluid/i', $useragent))
	{
		$link = 'http://www.fluidapp.com/';
		$title = 'Fluid';
		$code = 'fluid';
	}
	elseif (preg_match('/Focus/i', $useragent))
	{
		$link = 'http://www.mozilla.org/en-US/firefox/focus/';
		$title = 'Firefox Focus';
		$version = wpua_detect_browser_version('Focus');
		$code = 'firefox-focus';
	}
	elseif (preg_match('/FxiOS/i', $useragent))
	{
		$link = 'http://www.mozilla.org/firefox/ios/';
		$title = 'Firefox for iOS';
		$version = wpua_detect_browser_version('FxiOS');
		$code = 'firefox';
	}
	elseif (preg_match('/Galeon/i', $useragent))
	{
		$link = 'http://galeon.sourceforge.net/';
		$title = 'Galeon';
		$code = 'galeon';
	}
	elseif (preg_match('/GSA/i', $useragent)
		&& preg_match('/Mobile/i', $useragent))
	{
		$link = 'http://en.wikipedia.org/wiki/Google_Search#Mobile_app';
		$title = 'Google Search App';
		$version = wpua_detect_browser_version('GSA');
		$code = 'google';
	}
	elseif (preg_match('/IBrowse/i', $useragent)
		&& !preg_match('/MiuiBrowser/i', $useragent))
	{
		$link = 'http://www.ibrowse-dev.net/';
		$title = 'IBrowse';
		$code = 'ibrowse';
	}
	elseif (preg_match('/iCab/i', $useragent))
	{
		$link = 'http://www.icab.de/';
		$title = 'iCab';
		$code = 'icab';
	}
	elseif (preg_match('/IceCat/i', $useragent))
	{
		$link = 'http://gnuzilla.gnu.org/';
		$title = 'GNU IceCat';
		$version = wpua_detect_browser_version('IceCat');
		$code = 'icecat';
	}
	elseif (preg_match('/IceDragon/i', $useragent))
	{
		$link = 'http://www.comodo.com/home/browsers-toolbars/icedragon-browser.php';
		$title = 'IceDragon';
		$code = 'icedragon';
	}
	elseif (preg_match('/IceWeasel/i', $useragent))
	{
		$link = 'http://www.geticeweasel.org/';
		$title = 'IceWeasel';
		$code = 'iceweasel';
	}
	elseif (preg_match('/IEMobile/i', $useragent))
	{
		$link = 'http://www.microsoft.com/windowsmobile/en-us/downloads/microsoft/internet-explorer-mobile.mspx';
		$title = 'IEMobile';
		$code = 'msie-mobile';
	}
	elseif (preg_match('/Jasmine/i', $useragent))
	{
		$link = 'http://www.samsungmobile.com/';
		$title = 'Jasmine';
		$code = 'samsung';
	}
	elseif (preg_match('/K-Meleon/i', $useragent))
	{
		$link = 'http://kmeleon.sourceforge.net/';
		$title = 'K-Meleon';
		$code = 'kmeleon';
	}
	elseif (preg_match('/Kinza/i', $useragent))
	{
		$link = 'http://www.kinza.jp/';
		$title = 'Kinza';
		$code = 'kinza';
	}
	elseif (preg_match('/KMLite/i', $useragent))
	{
		$link = 'http://en.wikipedia.org/wiki/K-Meleon';
		$title = 'KMLite';
		$code = 'kmeleon';
	}
	elseif (preg_match('/Konqueror/i', $useragent))
	{
		$link = 'http://konqueror.kde.org/';
		$title = 'Konqueror';
		$code = 'konqueror';
	}
	elseif (preg_match('/Kylo/i', $useragent))
	{
		$link = 'http://kylo.tv/';
		$title = 'Kylo';
		$code = 'kylo';
	}
	elseif (preg_match('/LBrowser/i', $useragent))
	{
		$link = 'http://wiki.freespire.org/index.php/Web_Browser';
		$title = 'LBrowser';
		$code = 'lbrowser';
	}
	elseif (preg_match('/LG Browser/i', $useragent))
	{
		$link = 'http://developer.lgappstv.com/TV_HELP/index.jsp?topic=%2Flge.tvsdk.developing.book%2Fhtml%2FDeveloping+Web+App%2FDeveloping+Web+App%2FWeb+Engine.htm';
		$title = 'LG Web Browser';
		$version = wpua_detect_browser_version('Browser');
		$code = 'lgbrowser';
	}
	elseif (preg_match('/LeechCraft/i', $useragent))
	{
		$link = 'http://leechcraft.org/';
		$title = 'LeechCraft';
		$version = '';
		$code = 'leechcraft';
	}
	elseif (preg_match('/Links/i', $useragent)
		&& !preg_match('/online\ link\ validator/i', $useragent))
	{
		$link = 'http://links.twibright.com/';
		$version = wpua_detect_browser_version('Links \\(');
		$title = 'Links';
		$code = 'links';
	}
	elseif (preg_match('/Lobo/i', $useragent))
	{
		$link = 'http://www.lobobrowser.org/';
		$title = 'Lobo';
		$code = 'lobo';
	}
	elseif (preg_match('/luakit/i', $useragent))
	{
		$link = 'http://luakit.org/';
		$title = 'luakit';
		$version = '';
		$code = 'luakit';
	}
	elseif (preg_match('/Lunascape/i', $useragent))
	{
		$link = 'http://www.lunascape.tv';
		$title = 'Lunascape';
		$code = 'lunascape';
	}
	elseif (preg_match('/Lynx/i', $useragent))
	{
		$link = 'http://lynx.browser.org/';
		$title = 'Lynx';
		$code = 'lynx';
	}
	elseif (preg_match('/Maxthon/i', $useragent))
	{
		$link = 'http://www.maxthon.com/';
		$title = 'Maxthon';
		$code = 'maxthon';
	}
	elseif (preg_match('/\ MIB\//i', $useragent))
	{
		$link = 'http://www.motorola.com/content.jsp?globalObjectId=1827-4343';
		$title = 'MIB';
		$code = 'mib';
	}
	elseif (preg_match('/Midori/i', $useragent))
	{
		$link = 'http://www.twotoasts.de/index.php?/pages/midori_summary.html';
		$title = 'Midori';
		$code = 'midori';
	}
	elseif (preg_match('/ min\//i', $useragent))
	{
		$link = 'https://github.com/minbrowser/min';
		$title = 'Min Browser';
		$version = wpua_detect_browser_version('min');
		$code = 'min';
	}
	elseif (preg_match('/MiuiBrowser/i', $useragent))
	{
		$link = 'https://en.wikipedia.org/wiki/MIUI';
		$title = 'MIUI Browser';
		$version = wpua_detect_browser_version('MiuiBrowser');
		$code = 'miuibrowser';
	}
	elseif (preg_match('/MozillaDeveloperPreview/i', $useragent))
	{
		$link = 'http://www.mozilla.org/projects/devpreview/releasenotes/';
		$title = 'Mozilla Developer Preview';
		$version = wpua_detect_browser_version('MozillaDeveloperPreview');
		$code = 'firefoxdevpre';
	}
	elseif (preg_match('/MQQBrowser/i', $useragent)
		|| preg_match('/QQBrowser/i', $useragent))
	{
		$link = 'http://browser.qq.com/';
		$title = 'QQbrowser';
		if (preg_match('/MQQBrowser/i', $useragent))
		{
			$version = '';
		}
		$code = 'qqbrowser';
	}
	elseif (preg_match('/NetFront/i', $useragent))
	{
		$link = 'http://www.access-company.com/';
		$title = 'NetFront';
		$code = 'netfront';
	}
	elseif (preg_match('/NetSurf/i', $useragent))
	{
		$link = 'http://www.netsurf-browser.org/';
		$title = 'NetSurf';
		$code = 'netsurf';
	}
	elseif (preg_match('/NF-Browser/i', $useragent))
	{
		$link = 'http://www.access-company.com/';
		$title = 'NetFront';
		$version = wpua_detect_browser_version('NF-Browser');
		$code = 'netfront';
	}
	elseif (preg_match('/Nintendo 3DS/i', $useragent))
	{
		$link = 'http://en.wikipedia.org/wiki/Internet_Browser_(Nintendo_3DS)';
		$title = 'Nintendo 3DS';
		$version = '';
		$code = 'nintendo3dsbrowser';
	}
	elseif (preg_match('/OmniWeb/i', $useragent))
	{
		$link = 'http://www.omnigroup.com/applications/omniweb/';
		$title = 'OmniWeb';
		$code = 'omniweb';
	}
	elseif (preg_match('/Opera Mini/i', $useragent))
	{
		$link = 'http://www.opera.com/mini/';
		$title = 'Opera Mini';
		$code = 'opera-mini';
	}
	elseif (preg_match('/Opera Mobi/i', $useragent))
	{
		$link = 'http://www.opera.com/mobile/';
		if (preg_match('/Version/i', $useragent))
		{
			$version = wpua_detect_browser_version('Version');
		}
		else
		{
			$version = wpua_detect_browser_version('Opera Mobi');
		}
		$title = 'Opera Mobile';
		$code = 'opera';
	}
	elseif (preg_match('/Opera/i', $useragent)
		|| preg_match('/OPR\/(\S+)/', $useragent))
	{
		$link = 'http://www.opera.com/';
		$title = 'Opera';
		$code = 'opera';

		// How is version stored on this Opera ua?
		if (preg_match('/Version/i', $useragent))
		{
			$version = wpua_detect_browser_version('Version');
		}
		elseif (preg_match('/OPR/i', $useragent))
		{
			$version = wpua_detect_browser_version('OPR');
		}
		else
		{
			// Use Opera as fallback since full title may change (Next, Developer, etc.)
			$version = wpua_detect_browser_version('Opera');
		}

		// Is this one with a known alternate icon?
		if (preg_match('/Opera Labs/i', $useragent)
			|| preg_match('/Edition Labs/i', $useragent))
		{
			$code = 'opera-beta';
		}
		elseif (preg_match('/Opera Next/i', $useragent)
			|| preg_match('/Edition Next/i', $useragent))
		{
			$code = 'opera-beta';
		}
		elseif (preg_match('/Opera Developer/i', $useragent)
			|| preg_match('/Edition Developer/i', $useragent))
		{
			$code = 'opera-dev';
		}

		// Parse full edition name, ex: Opera/9.80 (X11; Linux x86_64; U; Edition Labs Camera and Pages; Ubuntu/11.10; en) Presto/2.9.220 Version/12.00
		if (preg_match('/Edition ([\ ._0-9a-zA-Z]+)/i', $useragent, $regmatch))
		{
			$title .= ' '.$regmatch[1];
		}
		elseif (preg_match('/Opera ([\ ._0-9a-zA-Z]+)/i', $useragent, $regmatch))
		{
			$title .= ' '.$regmatch[1];
		}
	}
	elseif (preg_match('/Otter/i', $useragent))
	{
		$link = 'http://otter-browser.org/';
		$title = 'Otter';
		$code = 'otter';
	}
	elseif (preg_match('/Palemoon/i', $useragent))
	{
		$link = 'http://www.palemoon.org/';
		$title = 'Pale Moon';
		$version = wpua_detect_browser_version('Moon');
		$code = 'palemoon';
	}
	elseif (preg_match('/Phoenix/i', $useragent))
	{
		$link = 'http://www.mozilla.org/projects/phoenix/phoenix-release-notes.html';
		$title = 'Phoenix';
		$code = 'phoenix';
	}
	elseif (preg_match('/PlayStation\ 4/i', $useragent))
	{
		$link = 'http://us.playstation.com/';
		$title = 'PS4 Web Browser';
		$version = '';
		$code = 'ps4browser';
	}
	elseif (preg_match('/Polarity/i', $useragent))
	{
		$link = 'http://polarityweb.webs.com/';
		$title = 'Polarity';
		$code = 'polarity';
	}
	elseif (preg_match('/Puffin/i', $useragent))
	{
		$link = 'http://www.puffin.com/';
		$title = 'Puffin';
		$code = 'puffin';
	}
	elseif (preg_match('/Falkon/i', $useragent))
	{
		$link = 'http://www.falkon.org/';
		$title = 'Falkon';
		$code = 'falkon';
	}
	elseif (preg_match('/Roccat/i', $useragent))
	{
		$link = 'http://www.runecats.com/roccat.html';
		$title = 'Roccat';
		$code = 'roccatbrowser';
	}
	elseif (preg_match('/SaaYaa/i', $useragent))
	{
		$link = 'http://www.saayaa.com/';
		$title = 'SaaYaa Explorer';
		$version = '';
		$code = 'saayaa';
	}
	elseif (preg_match('/SeaMonkey/i', $useragent))
	{
		$link = 'http://www.seamonkey-project.org/';
		$title = 'SeaMonkey';
		$code = 'seamonkey';
	}
	elseif (preg_match('/SEMC-Browser/i', $useragent))
	{
		$link = 'http://www.sonyericsson.com/';
		$title = 'SEMC Browser';
		$version = wpua_detect_browser_version('SEMC-Browser');
		$code = 'semcbrowser';
	}
	elseif (preg_match('/SEMC-java/i', $useragent))
	{
		$link = 'http://www.sonyericsson.com/';
		$title = 'SEMC-java';
		$code = 'semcbrowser';
	}
	elseif (preg_match('/SE\ /i', $useragent)
		&& preg_match('/MetaSr/i', $useragent))
	{
		$link = 'http://ie.sogou.com/';
		$title = 'Sogou Explorer';
		$version = '';
		$code = 'sogou';
	}
	elseif (preg_match('/Seznam\.cz/i', $useragent))
	{
		$link = 'http://www.seznam.cz/prohlizec';
		$title = 'Seznam.cz';
		$version = wpua_detect_browser_version('cz');
		$code = 'seznam-cz';
	}
	elseif (preg_match('/Silk/i', $useragent)
		&& !preg_match('/PlayStation/i', $useragent))
	{
		$link = 'http://en.wikipedia.org/wiki/Amazon_Silk';
		$title = 'Amazon Silk';
		$version = wpua_detect_browser_version('Silk');
		$code = 'silk';
	}
	elseif (preg_match('/SiteKiosk/i', $useragent))
	{
		$link = 'http://www.sitekiosk.com/SiteKiosk/Default.aspx';
		$title = 'SiteKiosk';
		$code = 'sitekiosk';
	}
	elseif (preg_match('/Sleipnir/i', $useragent))
	{
		$link = 'http://www.fenrir-inc.com/other/sleipnir/';
		$title = 'Sleipnir';
		$code = 'sleipnir';
	}
	elseif (preg_match('/SlimBrowser/i', $useragent))
	{
		$link = 'http://www.flashpeak.com/sbrowser/';
		$title = 'SlimBrowser';
		$code = 'slimbrowser';
	}
	elseif (preg_match('/Superbird/i', $useragent))
	{
		$link = 'http://superbird-browser.com/';
		$title = 'Superbird';
		$code = 'superbird';
	}
	elseif (preg_match('/Surf/i', $useragent))
	{
		$link = 'http://surf.suckless.org/';
		$title = 'Surf';
		$code = 'surf';
	}
	elseif (preg_match('/Swiftfox/i', $useragent))
	{
		$link = 'http://www.getswiftfox.com/';
		$title = 'Swiftfox';
		$code = 'swiftfox';
	}
	elseif (preg_match('/TenFourFox/i', $useragent))
	{
		$link = 'http://en.wikipedia.org/wiki/TenFourFox';
		$title = 'TenFourFox';
		$version = wpua_detect_browser_version(' rv');
		$code = 'tenfourfox';
	}
	elseif (preg_match('/QtCarBrowser/i', $useragent))
	{
		$link = 'http://www.teslamotors.com/';
		$title = 'Tesla Car Browser';
		$version = '';
		$code = 'teslacarbrowser';
	}
	elseif (preg_match('/TheWorld/i', $useragent))
	{
		$link = 'http://www.theworld.cn/';
		$title = 'TheWorld Browser';
		$version = '';
		$code = 'theworld';
	}
	elseif (preg_match('/Thunderbird/i', $useragent))
	{
		$link = 'http://www.thunderbird.net/';
		$title = 'Thunderbird';
		$code = 'thunderbird';
	}
	elseif (preg_match('/Tizen/i', $useragent))
	{
		$link = 'https://www.tizen.org/';
		$title = 'Tizen';
		$code = 'tizen';
	}
	elseif (preg_match('/UBrowser/i', $useragent))
	{
		$link = 'http://www.ucweb.com/';
		$title = 'UC Browser';
		$version = wpua_detect_browser_version('UBrowser');
		$code = 'ucbrowser';
	}
	elseif (preg_match('/UCBrowser/i', $useragent))
	{
		$link = 'http://www.ucweb.com/';
		$title = 'UC Browser';
		$version = wpua_detect_browser_version('UCBrowser');
		$code = 'ucbrowser';
	}
	elseif (preg_match('/UC\ Browser/i', $useragent))
	{
		$link = 'http://www.ucweb.com/';
		$title = 'UC Browser';
		$code = 'ucbrowser';
	}
	elseif (preg_match('/UCMini/i', $useragent))
	{
		$link = 'http://www.ucweb.com/';
		$title = 'UC Browser Mini';
		$version = wpua_detect_browser_version('UCMini');
		$code = 'ucbrowser-mini';
	}
	elseif (preg_match('/UCWEB/i', $useragent))
	{
		$link = 'http://www.ucweb.com/';
		$title = 'UC Browser';
		$version = wpua_detect_browser_version('UCWEB');
		$code = 'ucweb';
	}
	elseif (preg_match('/uzbl/i', $useragent))
	{
		$link = 'http://www.uzbl.org/';
		$title = 'uzbl';
		$code = 'uzbl';
	}
	elseif (preg_match('/Vivaldi/i', $useragent))
	{
		$link = 'http://vivaldi.com/';
		$title = 'Vivaldi';
		$code = 'vivaldi';
	}
	elseif (preg_match('/w3m/i', $useragent))
	{
		$link = 'http://w3m.sourceforge.net/';
		$title = 'W3M';
		$code = 'w3m';
	}
	elseif (preg_match('/AppleWebkit/i', $useragent)
		&& preg_match('/Android/i', $useragent)
		&& !preg_match('/Chrome/i', $useragent))
	{
		$link = 'http://developer.android.com/reference/android/webkit/package-summary.html';
		$title = 'Android Webkit';
		$version = wpua_detect_browser_version('Version');
		$code = 'android-webkit';
	}
	elseif (preg_match('/Waterfox/i', $useragent))
	{
		$link = 'http://www.waterfoxproject.org/';
		$title = 'Waterfox';
		$code = 'waterfox';
	}
	elseif (preg_match('/WebianShell/i', $useragent))
	{
		$link = 'http://webian.org/shell/';
		$title = 'Webian Shell';
		$version = wpua_detect_browser_version('Shell');
		$code = 'webianshell';
	}
	elseif (preg_match('/Chrome/i', $useragent)
		&& preg_match('/Mobile/i', $useragent)
		&& ( preg_match('/Version/i', $useragent)
			|| preg_match('/wv/i', $useragent) ))
	{
		// https://developer.chrome.com/multidevice/user-agent
		$link = 'https://developer.chrome.com/multidevice/webview/overview';
		$title = 'WebView';
		$version = wpua_detect_browser_version('Version');
		$code = 'android-webkit';
	}
	elseif (preg_match('/WorldWideWeb/i', $useragent))
	{
		$link = 'http://www.w3.org/People/Berners-Lee/WorldWideWeb.html';
		$title = 'WorldWideWeb';
		$code = 'worldwideweb';
	}
	elseif (preg_match('/wp-android/i', $useragent))
	{
		$link = 'http://android.wordpress.org/';
		$version = wpua_detect_browser_version('wp-android'); //TODO check into Android version being returned
		$title = 'Wordpress App';
		$code = 'wordpress';
	}
	elseif (preg_match('/wp-blackberry/i', $useragent))
	{
		$link = 'http://blackberry.wordpress.org/';
		$title = 'wp-blackberry';
		$code = 'wordpress';
	}
	elseif (preg_match('/wp-iphone/i', $useragent))
	{
		$link = 'http://ios.wordpress.org/';
		$title = 'Wordpress App';
		$version = wpua_detect_browser_version('wp-iphone');
		$code = 'wordpress';
	}
	elseif (preg_match('/wp-nokia/i', $useragent))
	{
		$link = 'http://nokia.wordpress.org/';
		$title = 'wp-nokia';
		$code = 'wordpress';
	}
	elseif (preg_match('/wp-webos/i', $useragent))
	{
		$link = 'http://webos.wordpress.org/';
		$title = 'wp-webos';
		$code = 'wordpress';
	}
	elseif (preg_match('/wp-windowsphone/i', $useragent))
	{
		$link = 'http://windowsphone.wordpress.org/';
		$title = 'wp-windowsphone';
		$code = 'wordpress';
	}
	elseif (preg_match('/YaBrowser/i', $useragent))
	{
		$link = 'http://browser.yandex.com/';
		$title = 'Yandex Browser';
		$version = wpua_detect_browser_version('Browser');
		$code = 'yandex';
	}
	elseif (preg_match('/ZipZap/i', $useragent))
	{
		$link = 'http://www.zipzap.io/wordpress/';
		$title = 'ZipZap';
		$code = 'zipzap';
	}

	elseif (preg_match('/Edge\//i', $useragent) || preg_match('/Edg\//i', $useragent) || preg_match('/EdgiOS\//i', $useragent) || preg_match('/EdgA\//i', $useragent))
	{
		$link = 'https://www.microsoft.com/en-us/edge';
		$title = 'Microsoft Edge';
		
		if (preg_match('/Edge\//i', $useragent))
		{
			// Edge (MSIE rebrand and rewrite)
			$version = wpua_detect_browser_version('Edge');
			$code = 'edge-old';
		}
		else
		{
			if (preg_match('/EdgiOS\//i', $useragent))
			{
				// Edge for iOS
				$version = wpua_detect_browser_version('EdgiOS');
			}
			elseif (preg_match('/EdgA\//i', $useragent))
			{
				// Edge for Android
				$version = wpua_detect_browser_version('EdgA');
			}
			else
			{
				// Edge (Chromium)
				$version = wpua_detect_browser_version('Edg');
			}
			$code = 'edge';
		}
	}
	elseif (preg_match('/Chrome/i', $useragent))
	{
		$link = 'http://google.com/chrome/';
		$title = 'Google Chrome';
		$version = wpua_detect_browser_version('Chrome');
		$code = 'chrome';
	}
	elseif (preg_match('/Safari/i', $useragent)
		&& !preg_match('/Nokia/i', $useragent))
	{
		$link = 'http://www.apple.com/safari/';
		$title = 'Safari';

		if (preg_match('/Version/i', $useragent))
		{
			$version = wpua_detect_browser_version('Version');
		}

		if (preg_match('/Mobile Safari/i', $useragent))
		{
			$title = 'Mobile '.$title;
		}

		$code = 'safari';
	}
	elseif (preg_match('/Firefox/i', $useragent))
	{
		$link = 'http://www.mozilla.org/';
		$title = 'Firefox';
		$code = 'firefox';
	}
	elseif (preg_match('/MSIE/i', $useragent) || preg_match('/Trident/i', $useragent))
	{
		$link = 'http://www.microsoft.com/windows/products/winfamily/ie/default.mspx';
		$title = 'Internet Explorer';

		if (preg_match('/\ rv:([.0-9a-zA-Z]+)/i', $useragent))
		{
			// IE11 or newer
			$version = wpua_detect_browser_version(' rv');
		}
		else
		{
			// IE10 or older, regex: '/MSIE[\ |\/]?([.0-9a-zA-Z]+)/i'
			$version = wpua_detect_browser_version('MSIE');
		}

		if (intval($version) >= 11)
		{
			$code = 'msie11';
		}
		elseif (intval($version) >= 10)
		{
			$code = 'msie10';
		}
		elseif (intval($version) >= 9)
		{
			$code = 'msie9';
		}
		elseif (intval($version) >= 7)
		{
			// also ie8
			$code = 'msie7';

			// Detect compatibility mode for IE
			if ($version === '7.0' && preg_match('/Trident\/4.0/i', $useragent))
			{
				$version = '8.0 (Compatibility Mode)'; // Fix for IE8 quirky UA string with Compatibility Mode enabled
			}
		}
		elseif (intval($version) >= 6)
		{
			$code = 'msie6';
		}
		elseif (intval($version) >= 4)
		{
			// also ie5
			$code = 'msie4';
		}
		elseif (intval($version) >= 3)
		{
			$code = 'msie3';
		}
		elseif (intval($version) >= 2)
		{
			$code = 'msie2';
		}
		elseif (intval($version) >= 1)
		{
			$code = 'msie1';
		}
		else
		{
			$code = 'msie';
		}
	}
	elseif (preg_match('/Mozilla/i', $useragent))
	{
		$link = 'http://www.mozilla.org/';
		$title = 'Mozilla';
		$version = wpua_detect_browser_version(' rv');

		if (empty($version))
		{
			$title .= ' Compatible';
		}

		$code = 'mozilla';
	}

	// No Web browser match
	else
	{
		$link = '#';
		$title = 'Unknown';
		$version = '';
		$code = 'null';
	}

	// Set version if it hasn't been parsed yet (generic structure)...
	if (is_null($version))
	{
		$version = wpua_detect_browser_version($title);
	}

	// Append version to title (as long as show version isn't 'off')
	if ($wpua_show_version !== 'false')
	{
		$title .= " $version";
	}

	return wpua_get_icon_text($link, $title, $code, '/net/');
}

?>
