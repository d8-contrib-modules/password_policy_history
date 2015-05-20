<?php

/**
 * @file
 * Contains Drupal\password_policy_history\Constraints\PasswordHistory.
 */


namespace Drupal\password_policy_history\Plugin\PasswordConstraint;

use Drupal\Core\Form\FormStateInterface;
use Drupal\password_policy\PasswordConstraintBase;
use Drupal\password_policy\PasswordPolicyValidation;
use Drupal\Core\Password\PasswordInterface;

/**
 * Enforces a specific character length for passwords.
 *
 * @PasswordConstraint(
 *   id = "password_policy_history_constraint",
 *   title = @Translation("Password History"),
 *   description = @Translation("Provide restrictions on previously used passwords."),
 *   error_message = @Translation("You have used the same password previously and cannot."),
 * )
 */
class PasswordHistory extends PasswordConstraintBase {

  /**
   * {@inheritdoc}
   */
  function validate($password, $user_context) {
    $configuration = $this->getConfiguration();
    $validation = new PasswordPolicyValidation();
    var_dump($user_context);

    if (empty($user_context['uid'])) {
      return $validation;
    }

    $hashed_pass = \Drupal::service('password')->hash(trim($password));
    var_dump($hashed_pass);

    //query for number of repeated by user
    $repeated_rows = db_query('password_policy_history', 'pph')
      ->fields('pph', array())
      ->condition('uid', $user_context['uid'])
      ->condition('pass_hash', $hashed_pass)
      ->execute()
      ->fetchAll();

    if (count($repeated_rows)!=0 and count($repeated_rows)>= $configuration['history_repeats']) {
      $validation->setErrorMessage($this->t('You cannot use the same password @history-repeats and this has been used @number-repeats', array('@history-repeats'=>$configuration['history_repeats'], '@number-repeats'=>count($repeated_rows))));
    }
    return $validation;
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'history_repeats' => 0,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form['history_repeats'] = array(
      '#type' => 'textfield',
      '#title' => t('Number of allowed repeated passwords'),
      '#description' => 'A value of 0 represents no allowed repeats',
      '#default_value' => $this->getConfiguration()['history_repeats'],
    );
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    if (!is_numeric($form_state->getValue('history_repeats')) or $form_state->getValue('history_repeats') < 0) {
      $form_state->setErrorByName('history_repeats', $this->t('The number of repeated passwords value must be zero or greater.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $this->configuration['history_repeats'] = $form_state->getValue('history_repeats');
  }

  /**
   * {@inheritdoc}
   */
  public function getSummary() {
    return $this->t('Number of allowed repeated passwords @number-repeats', array('@number-repeats' => $this->configuration['history_repeats']));
  }

}