module Payonline
  class PaymentResponse
    extend Forwardable

    attr_accessor :data, :params

    SIGNED_PARAMS = %i(date_time transaction_id order_id amount currency)

    def_delegators :data, *SIGNED_PARAMS

    def initialize(params = {})
      @params = prepare_params(params)
      @data = OpenStruct.new(@params)
    end

    def valid_payment?
      keys = SIGNED_PARAMS.select { |key| @params.key?(key) }
      @params[:security_key] == Payonline::Signature.new(@params, keys, false).digest
    end

    private

    def prepare_params(params)
      params
        .transform_keys { |key| key.to_s.underscore }
        .permit(
          :order_id,
          :date_time,
          :transaction_id,
          :amount,
          :currency,
          :security_key,
          :content_type,
          :lang,
          :provider,
          :payment_amount,
          :payment_currency,
          :card_holder,
          :card_number,
          :eci
        )
        .to_h
        .with_indifferent_access
    end
  end
end
