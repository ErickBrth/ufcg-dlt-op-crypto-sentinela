import paho.mqtt.client as mqtt

client = mqtt.Client()
client.connect("test.mosquitto.org", 1883, 60)
client.publish("ufcg/cc/dlt/mensagens/para/UT-Alpha", "Olá, Cripto-Sentinela!")
client.disconnect()
