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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Volume" "Volume.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Volume" "Volume.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-VolumeSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-VolumeSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"]
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
Text=#VarHideVol#
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#VolumeHideVol#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "VolumeHideVol" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"][!Refresh "#ROOTCONFIG#\Circles\Volume"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#VolumeHideVol#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "VolumeHideVol" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"][!Refresh "#ROOTCONFIG#\Circles\Volume"][!Refresh]

[ButtonDescription3b]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarHideOutput#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#VolumeHideOutput#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "VolumeHideOutput" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"][!Refresh "#ROOTCONFIG#\Circles\Volume"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#VolumeHideOutput#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "VolumeHideOutput" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"][!Refresh "#ROOTCONFIG#\Circles\Volume"][!Refresh]

[ButtonDescription3c]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#VolumeColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "VolumeColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"][!Refresh "#ROOTCONFIG#\Circles\Volume"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#VolumeColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "VolumeColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Volume"][!Refresh "#ROOTCONFIG#\Circles\Volume"][!Refresh]


