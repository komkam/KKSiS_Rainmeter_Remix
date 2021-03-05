;---- Skin Toggle ----

[Background1]
Meter=Shape
Shape=Rectangle 10,35,100,95,3 | Fill Color 50,50,50

[Title1]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=40
Text=#VarToggle#

[Divider1]
Meter=Shape
Shape=Rectangle 12,55,96,2,0 | Fill Color 160,160,160

[Toggle1a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=20
Y=65
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Power" "Power.ini"]

[Toggle1aText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Panel Skin

[Toggle1b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=-30r
Y=23r
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Power" "Power.ini"]

[Toggle1bText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Circle Skin


;---- Panel Skin Size ----

[Background2]
Meter=Shape
Shape=Rectangle 120,35,100,95,3 | Fill Color 50,50,50

[Title2]
Meter=String
MeterStyle=SettingsStyle-Text
X=125
Y=40
Text=#VarPanelSize#

[Divider2]
Meter=Shape
Shape=Rectangle 122,55,96,2,0 | Fill Color 160,160,160

[Button2a]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=65
ButtonCommand=[!WriteKeyValue Variables "Panel-PowerSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"]
[Button2aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSmall#

[Button2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-PowerSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"]
[Button2bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSquare#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,95,3 | Fill Color 50,50,50

[Title3]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=40
Text=#VarOptions#

[Divider3]
Meter=Shape
Shape=Rectangle 232,55,156,2,0 | Fill Color 160,160,160

[ButtonDescription3a]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowTitle#
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#PowerHideTitle#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "PowerHideTitle" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"][!Refresh "#ROOTCONFIG#\Circles\Power"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#PowerHideTitle#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "PowerHideTitle" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"][!Refresh "#ROOTCONFIG#\Circles\Power"][!Refresh]

[ButtonDescription3b]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarHideBatStatus#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#PowerHideStatus#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "PowerHideStatus" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"][!Refresh "#ROOTCONFIG#\Circles\Power"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#PowerHideStatus#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "PowerHideStatus" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"][!Refresh "#ROOTCONFIG#\Circles\Power"][!Refresh]

[ButtonDescription3c]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#PowerColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "PowerColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"][!Refresh "#ROOTCONFIG#\Circles\Power"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#PowerColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "PowerColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Power"][!Refresh "#ROOTCONFIG#\Circles\Power"][!Refresh]


