package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import name.neuhalfen.projects.crypto.internal.Preconditions;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Defines strategies for signature checking.
 */
public final class SignatureValidationStrategies {

  // no instances
  private SignatureValidationStrategies() {
  }

  /**
   * Ignore signatures, EVEN BROKEN signatures! . Use this at your own peril.
   *
   * @return an instance of the requested strategy
   **/
  public static SignatureValidationStrategy ignoreSignatures() {
    return new IgnoreSignaturesValidationStrategy();
  }

  /**
   * Require any signature for a public key in the keyring.
   *
   * @return an instance of the requested strategy
   *
   * @see KeyringConfig#getPublicKeyRings()
   **/
  public static SignatureValidationStrategy requireAnySignature() {
    return new RequireAnySignatureValidationStrategy();
  }

  /**
   * Require signature from all of the passed uids.
   *
   * @param config keyring config
   * @param keySelectionStrategy the key selection strategy to use
   * @param userIds A list of user IDs (e.g. 'sender@example.com')
   *
   * @return an instance of the requested strategy
   *
   * @throws PGPException No or more than one public key found for a user id
   **/
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidLiteralsInIfCondition"})
  public static SignatureValidationStrategy requireSignatureFromAllUids(
      KeySelectionStrategy keySelectionStrategy,
      KeyringConfig config, String... userIds) throws PGPException {

    Preconditions.checkNotNull(keySelectionStrategy, "keySelectionStrategy must not be null");
    Preconditions.checkNotNull(config, "config must not be null");
    Preconditions.checkNotNull(userIds, "userIds must not be null");

    final Map<String, Set<Long>> keyIdsByUid = new HashMap<>();

    for (String userId : userIds) {

      final Set<PGPPublicKey> availableKeys;
      try {
        availableKeys = keySelectionStrategy
            .validPublicKeysForVerifyingSignatures(userId, config);
      } catch (IOException e) {
        throw new PGPException("Failed to extract keys", e);
      }

      if (availableKeys.isEmpty()) {
        throw new PGPException("Could not find public-key for userid '" + userId + "'");
      }

      Set<Long> keysForUid = availableKeys.stream().map(key -> key.getKeyID())
          .collect(Collectors.toSet());

      keyIdsByUid.put(userId, keysForUid);
    }
    return new RequireSpecificSignatureValidationForUserIdsStrategy(keyIdsByUid);
  }


  /**
   * <p>
   *   Require signature from all of the passed uids.
   * </p><p>
   * This only really works if each uid has EXACTLY one key.
   * </p>
   *
   * @param config keyring config
   * @param keySelectionStrategy the key selection strategy to use
   * @param userIds A list of user IDs (e.g. 'sender@example.com')
   *
   * @return an instance of the requested strategy
   *
   * @throws PGPException No or more than one public key found for a user id
   **/
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidLiteralsInIfCondition"})
  @Deprecated
  public static SignatureValidationStrategy requireSignatureFromAllKeys(
      KeySelectionStrategy keySelectionStrategy,
      KeyringConfig config, String... userIds) throws PGPException {

    Preconditions.checkNotNull(keySelectionStrategy, "keySelectionStrategy must not be null");
    Preconditions.checkNotNull(config, "config must not be null");
    Preconditions.checkNotNull(userIds, "userIds must not be null");

    final List<Long> keyIds = new ArrayList<>(userIds.length);

    for (String userId : userIds) {

      final Set<PGPPublicKey> availableKeys;
      try {
        availableKeys = keySelectionStrategy
            .validPublicKeysForVerifyingSignatures(userId, config);
      } catch (IOException e) {
        throw new PGPException("Failed to extract keys", e);
      }

      if (availableKeys.isEmpty()) {
        throw new PGPException("Could not find public-key for userid '" + userId + "'");
      }

      if (availableKeys.size() > 1) {
        throw new PGPException(
            "Found more than one (" + availableKeys.size() + ") keys for userid '" + userId + "'");
      }

      PGPPublicKey selectPublicKey = availableKeys.iterator().next();
      keyIds.add(selectPublicKey.getKeyID());
    }
    return new RequireSpecificSignatureValidationStrategy(keyIds);
  }


  /**
   * Require signature from all of the passed keys. . The IDs are 32 bit key-IDs (
   * --keyid-format=0xlong)
   *
   * @param signaturesRequiredForTheseKeys KeyIds (32 bit IDs)
   *
   * @return an instance of the requested strategy
   **/
  public static SignatureValidationStrategy requireSignatureFromAllKeys(
      Collection<Long> signaturesRequiredForTheseKeys) {
    return new RequireSpecificSignatureValidationStrategy(signaturesRequiredForTheseKeys);
  }

  /**
   * Require signature from all of the passed keys.
   *
   * @param keyIds The IDs are 32 bit key-IDs ( --keyid-format=0xlong)
   *
   * @return an instance of the requested strategy
   **/
  public static SignatureValidationStrategy requireSignatureFromAllKeys(Long... keyIds) {
    Preconditions.checkNotNull(keyIds, "keyIds must not be null");
    return new RequireSpecificSignatureValidationStrategy(Arrays.asList(keyIds));
  }

  /**
   * Require signature from a specific key.
   *
   * @param signaturesRequiredForThisKey The ID is a 32 bit key-ID ( --keyid-format=0xlong)
   *
   * @return an instance of the requested strategy
   **/
  public static SignatureValidationStrategy requireSignatureFromAllKeys(
      long signaturesRequiredForThisKey) {
    return new RequireSpecificSignatureValidationStrategy(
        Collections.singletonList(signaturesRequiredForThisKey));
  }
}
