package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;

import static java.util.Objects.requireNonNull;

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
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Defines strategies for signature checking.
 */
@SuppressWarnings({"PMD.ClassNamingConventions"})
public final class SignatureValidationStrategies {

  private SignatureValidationStrategies() {
    // no instances
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

    requireNonNull(keySelectionStrategy, "keySelectionStrategy must not be null");
    requireNonNull(config, "config must not be null");
    requireNonNull(userIds, "userIds must not be null");

    final Map<String, Set<Long>> keyIdsByUid = new HashMap<>();
    for (final String userId : userIds) {

      final Set<PGPPublicKey> availableKeys = validPublicKeysForVerifyingSignatures(
          keySelectionStrategy, config, userId);

      if (availableKeys.isEmpty()) {
        throw new PGPException("Could not find public-key for userid '" + userId + "'");
      }

      final Set<Long> keysForUid = availableKeys.stream().map(PGPPublicKey::getKeyID)
          .collect(Collectors.toSet());

      keyIdsByUid.put(userId, keysForUid);
    }
    return new RequireSpecificSignatureValidationForUserIdsStrategy(keyIdsByUid);
  }


  /**
   * <p>
   * Require signature from all of the passed uids.
   * </p><p>
   * This only really works if each uid has EXACTLY one key.
   * </p>
   *
   * @param keySelectionStrategy the key selection strategy to use
   * @param config keyring config
   * @param userIds A list of user IDs (e.g. 'sender@example.com')
   *
   * @return an instance of the requested strategy
   *
   * @throws PGPException No or more than one public key found for a user id
   **/
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidLiteralsInIfCondition"})
  @Deprecated
  public static SignatureValidationStrategy requireSignatureFromAllKeys(
      final KeySelectionStrategy keySelectionStrategy,
      final KeyringConfig config,
      final String... userIds) throws PGPException {

    requireNonNull(keySelectionStrategy, "keySelectionStrategy must not be null");
    requireNonNull(config, "config must not be null");
    requireNonNull(userIds, "userIds must not be null");

    final List<Long> keyIds = new ArrayList<>(userIds.length);

    for (final String userId : userIds) {

      final Set<PGPPublicKey> availableKeys = validPublicKeysForVerifyingSignatures(
          keySelectionStrategy, config, userId);

      if (availableKeys.isEmpty()) {
        throw new PGPException("Could not find public-key for userid '" + userId + "'");
      }

      if (availableKeys.size() > 1) {
        throw new PGPException(
            "Found more than one (" + availableKeys.size() + ") keys for userid '" + userId + "'");
      }

      final PGPPublicKey selectPublicKey = availableKeys.iterator().next();
      keyIds.add(selectPublicKey.getKeyID());
    }
    return new RequireSpecificSignatureValidationStrategy(keyIds);
  }

  private static Set<PGPPublicKey> validPublicKeysForVerifyingSignatures(
      final KeySelectionStrategy keySelectionStrategy,
      final KeyringConfig config, final String userId) throws PGPException {
    try {
      return keySelectionStrategy
          .validPublicKeysForVerifyingSignatures(userId, config);
    } catch (IOException e) {
      throw new PGPException("Failed to extract keys", e);
    }
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
    requireNonNull(keyIds, "keyIds must not be null");
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
