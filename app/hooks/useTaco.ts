import { useContext } from "react";
import { DIDSession } from "did-session";
import { OrbisConnectResult, SiwxAttestation } from "@useorbis/db-sdk";
import { SiweMessage } from "@didtools/cacao";
import {
  conditions,
  decrypt,
  encrypt,
  ThresholdMessageKit,
} from "@nucypher/taco";
import {
  SingleSignOnEIP4361AuthProvider,
  USER_ADDRESS_PARAM_EXTERNAL_EIP4361,
} from "@nucypher/taco-auth";
import { ethers } from "ethers";
import { TACoContext } from "../context/TACoContext";

export default function useTaco() {
  const { isInitialized, ritualId, domain } = useContext(TACoContext);

  async function encryptWithTACo(
    messageToEncrypt: string,
    condition: conditions.condition.Condition,
    provider: ethers.providers.Provider,
    signer: ethers.Signer,
  ) {
    if (!isInitialized) return;

    const tmk = await encrypt(
      provider,
      domain,
      messageToEncrypt,
      condition,
      ritualId,
      signer,
    );

    return encodeB64(tmk.toBytes());
  }

  async function decryptWithTACo(
    encryptedMessage: string,
    provider: ethers.providers.Provider,
    signer: ethers.Signer,
  ) {
    if (!isInitialized) return;

    const siweInfo = await loadSiweFromOrbisSession(signer);
    if (!siweInfo) {
      console.error("No valid SIWE info found");
      return;
    }

    const tmk = ThresholdMessageKit.fromBytes(decodeB64(encryptedMessage));

    const authProvider =
      await SingleSignOnEIP4361AuthProvider.fromExistingSiweInfo(
        siweInfo.messageStr,
        siweInfo.signature,
      );

    const conditionContext =
      conditions.context.ConditionContext.fromMessageKit(tmk);
    conditionContext.addAuthProvider(
      USER_ADDRESS_PARAM_EXTERNAL_EIP4361,
      authProvider,
    );

    try {
      const decrypted = await decrypt(provider, domain, tmk, conditionContext);
      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error("Decryption failed:", error);
      return encryptedMessage;
    }
  }

  async function loadSiweFromOrbisSession(signer: ethers.Signer) {
    const sessionStr = JSON.parse(localStorage.getItem("orbis:session") ?? "{}")
      .session.session;

    if (!sessionStr) return;

    const session = await DIDSession.fromSession(sessionStr);
    const siweMessage = SiweMessage.fromCacao(session.cacao);
    const messageStr = siweMessage.toMessageEip55();
    const signature = siweMessage.signature;

    if (!signature) return;

    return { messageStr, signature };
  }

  function encodeB64(uint8Array: any) {
    return Buffer.from(uint8Array).toString("base64") as String;
  }

  function decodeB64(b64String: any) {
    return new Uint8Array(Buffer.from(b64String, "base64"));
  }

  return { isInitialized, encryptWithTACo, decryptWithTACo };
}
