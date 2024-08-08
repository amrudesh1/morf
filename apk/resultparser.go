package apk

import (
	"github.com/amrudesh1/morf/models"
	"github.com/amrudesh1/morf/utils"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	vip "github.com/spf13/viper"
)

func ParseResults(fs afero.Fs, fileName string, json_data []byte, secret models.Secrets, secret_data []byte) {
	utils.WriteToFile(fs, vip.GetString("backup_path")+fileName+"_"+secret.APKVersion+".json", string(json_data))
	utils.WriteToFile(fs, vip.GetString("backup_path")+fileName+"_"+"Secrets_"+secret.APKVersion+".json", string(secret_data))
	utils.WriteToFile(fs, "results"+"/"+fileName+"_"+secret.APKVersion+".json", string(json_data))
	utils.WriteToFile(fs, "results"+"/"+fileName+"_"+"Secrets_"+secret.APKVersion+".json", string(secret_data))
	log.Info("APK Data saved to: " + vip.GetString("backup_path") + "/" + fileName + "_" + secret.APKVersion + ".json")

}
